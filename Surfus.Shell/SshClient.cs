using NLog;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using Surfus.Shell.Messages.UserAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    /// <summary>
    /// SshClient is an SSH client that can be used to connect to an SSH server.
    /// </summary>
    public class SshClient : IDisposable
    {
        /// <summary>
        /// _logger is the logging mechanism. 
        /// </summary>
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// _readLoopTask holds the task of the read loop.
        /// </summary>
        private Task _readLoopTask;

        /// <summary>
        /// _clientSemaphore forces single access to objects of the SshClient.
        /// </summary>
        private SemaphoreSlim _clientSemaphore = new SemaphoreSlim(1,1);

        /// <summary>
        /// _sshClientState holds the state of the SshClient.
        /// </summary>
        private State _sshClientState = State.Intitial;

        /// <summary>
        /// InitialKeyExchangeCompleted synchronizes other actions to start once the initial key exchange has been completed.
        /// </summary>
        private TaskCompletionSource<bool> _initialKeyExchangeCompleted { get; set; }

        /// <summary>
        /// LoginCompleted represents the current state of authentication.
        /// </summary>
        private TaskCompletionSource<bool> _loginCompleted { get; set; }

        /// <summary>
        /// _channelCounter holds the current channel index used to derive new channel IDs.
        /// </summary>
        private uint _channelCounter = 0;

        /// <summary>
        /// _channels holds a list of the channels associated to this SshClient.
        /// </summary>
        private List<SshChannel> _channels = new List<SshChannel>();

        /// <summary>
        /// _disposables holds a list of the disposable objects.
        /// </summary>
        private List<IDisposable> _disposables = new List<IDisposable>();

        /// <summary>
        /// _isDisposed holds the disposed state of the SshClient.
        /// </summary>
        private bool _isDisposed = false;

        /// <summary>
        /// _tcpConnection holds the underlying TCP Connection of the SshClient.
        /// </summary>
        private TcpClient _tcpConnection = new TcpClient();

        /// <summary>
        /// _tcpStream holds the underlying NetworkStream of the TCP Connection.
        /// </summary>
        private NetworkStream _tcpStream;

        /// <summary>
        /// InternalCancellation is the cancellation source used to cancel tasks.
        /// </summary>
        internal CancellationTokenSource InternalCancellation = new CancellationTokenSource();

        /// <summary>
        /// IsConnected determines if the SshClient is connected to the remote SSH server.
        /// </summary>
        public bool IsConnected => _tcpConnection?.Connected == true && !_isDisposed && _sshClientState == State.Connected;

        /// <summary>
        /// IsConnecting determines if the SshClient is connecting to the remote SSH server.
        /// </summary>
        private bool _isConnecting => _tcpConnection?.Connected == true && !_isDisposed && _sshClientState == State.Connecting;

        /// <summary>
        /// ConnectionInfo contains connection information of the SshClient.
        /// </summary>
        public SshConnectionInfo ConnectionInfo = new SshConnectionInfo();

        /// <summary>
        /// Banner holds the banner message sent by the SSH server after login. If null, no banner was sent.
        /// </summary>
        public string Banner { get; private set; } = null;

        /// <summary>
        /// An SshClient that can connect to the designated hostname and port 22.
        /// </summary>
        /// <param name="hostname">The remote SSH Server</param>
        public SshClient(string hostname) : this(hostname, 22)
        {
        }

        /// <summary>
        /// An SshClient that can connect designated hostname and port.
        /// </summary>
        /// <param name="hostname">The remote SSH Server</param>
        /// <param name="port">The remote SSH port</param>
        public SshClient(string hostname, ushort port)
        {
            ConnectionInfo.Hostname = hostname;
            ConnectionInfo.Port = port;
        }

        /// <summary>
        /// ConnectAsync connects to the SSH server with the specific username and password.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="password">The password to login with</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task ConnectAsync(string username, string password, CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, InternalCancellation.Token))
            {
                await _clientSemaphore.WaitAsync(linkedCancellation.Token);
                
                // Validate current state of SshClient
                if (_sshClientState != State.Intitial)
                {
                    switch(_sshClientState)
                    {
                        case State.Connecting:
                            throw new SshException($"{nameof(ConnectAsync)} is already in progress.");
                        case State.Connected:
                            throw new SshException($"{nameof(ConnectAsync)} is already connected.");
                        case State.Error:
                        case State.Closed:
                            throw new SshException($"{nameof(ConnectAsync)} had previously connected.");
                        default:
                            throw new SshException($"{nameof(ConnectAsync)} had an unknown error.");
                    }
                }

                // Set new state of SshClient
                _sshClientState = State.Connecting;

                // Set SshClient defaults
                ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
                ConnectionInfo.Authentication = new SshAuthentication(this);

                // Perform version exchange and key exchange
                linkedCancellation.Token.Register(() => _initialKeyExchangeCompleted?.TrySetCanceled());
                _initialKeyExchangeCompleted = new TaskCompletionSource<bool>();
                ConnectionInfo.ServerVersion = await ExchangeVersionAsync((linkedCancellation.Token));
                _logger.Info("Server Version: " + ConnectionInfo.ServerVersion);
                _readLoopTask = ReadLoop();
                await _initialKeyExchangeCompleted.Task;

                // Perform login
                _loginCompleted = new TaskCompletionSource<bool>();
                linkedCancellation.Token.Register(() => _loginCompleted?.TrySetCanceled());
                await ConnectionInfo.Authentication.LoginAsync(username, password, linkedCancellation.Token);
                await _loginCompleted.Task;

                // Set new state
                _sshClientState = State.Connected;

                _clientSemaphore.Release();
            }
        }

        /// <summary>
        /// ConnectAsync connects to the SSH server with the specific username and interactive login callback.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="interactiveResponse">interactiveResponse is a callback to a method for interactive login</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task ConnectAsync(string username, Func<string, CancellationToken, Task<string>> interactiveResponse, CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, InternalCancellation.Token))
            {
                await _clientSemaphore.WaitAsync(linkedCancellation.Token);

                // Validate current state of SshClient
                if (_sshClientState != State.Intitial)
                {
                    switch (_sshClientState)
                    {
                        case State.Connecting:
                            throw new SshException($"{nameof(ConnectAsync)} is already in progress.");
                        case State.Connected:
                            throw new SshException($"{nameof(ConnectAsync)} is already connected.");
                        case State.Error:
                        case State.Closed:
                            throw new SshException($"{nameof(ConnectAsync)} had previously connected.");
                        default:
                            throw new SshException($"{nameof(ConnectAsync)} had an unknown error.");
                    }
                }

                // Set new state of SshClient
                _sshClientState = State.Connecting;

                // Set SshClient defaults
                ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
                ConnectionInfo.Authentication = new SshAuthentication(this);

                // Perform version exchange and key exchange
                linkedCancellation.Token.Register(() => _initialKeyExchangeCompleted?.TrySetCanceled());
                _initialKeyExchangeCompleted = new TaskCompletionSource<bool>();
                ConnectionInfo.ServerVersion = await ExchangeVersionAsync((linkedCancellation.Token));
                _logger.Info("Server Version: " + ConnectionInfo.ServerVersion);
                _readLoopTask = ReadLoop();
                await _initialKeyExchangeCompleted.Task;

                // Perform login
                _loginCompleted = new TaskCompletionSource<bool>();
                linkedCancellation.Token.Register(() => _loginCompleted?.TrySetCanceled());
                await ConnectionInfo.Authentication.LoginAsync(username, interactiveResponse, linkedCancellation.Token);
                await _loginCompleted.Task;

                // Set new state
                _sshClientState = State.Connected;

                _clientSemaphore.Release();
            }
        }

        /// <summary>
        /// Requests a terminal from the SSH server.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the terminal request</param>
        /// <returns>A task representing the state of the terminal request</returns>
        public async Task<SshTerminal> CreateTerminalAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, InternalCancellation.Token))
            {
                await _clientSemaphore.WaitAsync(linkedCancellation.Token);

                // Validate current state of SshClient
                if (_sshClientState != State.Connected)
                {
                    _clientSemaphore.Release();
                    switch (_sshClientState)
                    {
                        case State.Intitial:
                        case State.Connecting:
                            throw new SshException($"{nameof(SshClient)} has not yet connected.");
                        case State.Error:
                        case State.Closed:
                            throw new SshException($"{nameof(SshClient)} is no longer connected.");
                        default:
                            throw new SshException($"{nameof(SshClient)} had an unknown error.");
                    }
                }

                // Setup the new terminal
                var channel = new SshChannel(this, _channelCounter);
                var terminal = new SshTerminal(this, channel);

                _channels.Add(channel);
                _disposables.Add(terminal);
                _channelCounter++;

                _clientSemaphore.Release();
                return terminal;
            }
        }

        /// <summary>
        /// Requests the result of a command from the SSH server.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the terminal request</param>
        /// <returns>A task representing the state of the terminal request</returns>
        public async Task<SshCommand> CreateCommandAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, InternalCancellation.Token))
            {
                await _clientSemaphore.WaitAsync(linkedCancellation.Token);

                // Validate current state of SshClient
                if (_sshClientState != State.Connected)
                {
                    _clientSemaphore.Release();
                    switch (_sshClientState)
                    {
                        case State.Intitial:
                        case State.Connecting:
                            throw new SshException($"{nameof(SshClient)} has not yet connected.");
                        case State.Error:
                        case State.Closed:
                            throw new SshException($"{nameof(SshClient)} is no longer connected.");
                        default:
                            throw new SshException($"{nameof(SshClient)} had an unknown error.");
                    }
                }

                // Setup the new terminal
                var channel = new SshChannel(this, _channelCounter);
                var command = new SshCommand(this, channel);

                _channels.Add(channel);
                _disposables.Add(command);
                _channelCounter++;

                _clientSemaphore.Release();
                return command;
            }
        }

        /// <summary>
        /// Initiates the SSH connection by exchanging versions.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token used to cancel the version exchange.</param>
        /// <returns>A task representing the state of the version exchange</returns>
        private async Task<string> ExchangeVersionAsync(CancellationToken cancellationToken)
        {
            await _tcpConnection.ConnectAsync(ConnectionInfo.Hostname, ConnectionInfo.Port);
            _tcpStream = _tcpConnection.GetStream();
            var serverVersionFilter = new Regex(@"^SSH-(?<ProtoVersion>\d\.\d+)-(?<SoftwareVersion>\S+)(?<Comments>\s[^\r\n]+)?", RegexOptions.Compiled);

            // Buffer to receive their version.
            var buffer = new byte[ushort.MaxValue];
            var bufferPosition = 0;

            while (_tcpStream.CanRead)
            {
                if (bufferPosition == ushort.MaxValue)
                {
                    throw new ArgumentOutOfRangeException();
                }

                var readAmount = await _tcpStream.ReadAsync(buffer, bufferPosition, 1, cancellationToken);
                if (readAmount <= 0)
                {
                    _logger.Fatal($"{ConnectionInfo.Hostname} - { nameof(ExchangeVersionAsync)}: Read Amount: {readAmount}, BufferPosition: {bufferPosition}");
                    if (bufferPosition == 0)
                    {
                        _logger.Fatal($"{ConnectionInfo.Hostname} - { nameof(ExchangeVersionAsync)}: Buffer Position is 0, no data sent. Possibly too many connections");
                        throw new EndOfStreamException($"Buffer Position is 0, no data sent. Possibly too many connections");
                    }
                    throw new EndOfStreamException($"Read Amount: {readAmount}, BufferPosition: {bufferPosition}");
                }

                if (buffer[bufferPosition] == '\0')
                {
                    throw new InvalidDataException();
                }

                if (bufferPosition > 1 && buffer[bufferPosition] == '\n')
                {
                    var serverVersion = buffer[bufferPosition - 1] == '\r'
                                            ? Encoding.UTF8.GetString(buffer, 0, bufferPosition + readAmount - 2)
                                            : Encoding.UTF8.GetString(buffer, 0, bufferPosition + readAmount - 1);
                    var serverVersionMatch = serverVersionFilter.Match(serverVersion);
                    if (serverVersionMatch.Success)
                    {
                        if (serverVersionMatch.Groups["ProtoVersion"].Value == "2.0" || serverVersionMatch.Groups["ProtoVersion"].Value == "1.99")
                        {

                            // Send our version after. Seems to be a bug with some IOS versions if we're to fast and send this first.
                            var clientVersionBytes = Encoding.UTF8.GetBytes(ConnectionInfo.ClientVersion + "\n");
                            await _tcpStream.WriteAsync(clientVersionBytes, 0, clientVersionBytes.Length, cancellationToken);
                            await _tcpStream.FlushAsync(cancellationToken);

                            return serverVersion;
                        }
                    }

                    buffer = new byte[ushort.MaxValue];
                    bufferPosition = 0;
                }
                bufferPosition += readAmount;
            }


            throw new SshException("Invalid version from server");
        }

        /// <summary>
        /// ReadLoop continually checks for messages from the server. Long running Synchronous operations may block this method and cause a timeout.
        /// </summary>
        /// <returns></returns>
        private async Task ReadLoop()
        {
            try
            {
                _logger.Info("Starting Message Read Loop...");
                while ((IsConnected || _isConnecting) && !InternalCancellation.IsCancellationRequested)
                {
                    await ReadMessageAsync(InternalCancellation.Token);
                }
            }
            catch (Exception ex)
            {
                if (!_isDisposed)
                {
                    if(!InternalCancellation.IsCancellationRequested)
                    {
                        InternalCancellation.Cancel(true);
                    }
                    _logger.Fatal("Caught Exception in Read Loop: " + ex.ToString());
                }
            }
            finally
            {
                _logger.Info("Ending Message Read Loop...");
            }
        }

        /// <summary>
        /// Reads a message from the server
        /// </summary>
        /// <param name="cancellationToken">The cancellation token is used to cancel the ReadMessage request</param>
        /// <returns></returns>
        private async Task ReadMessageAsync(CancellationToken cancellationToken)
        {
            var sshPacket = await ConnectionInfo.ReadCryptoAlgorithm.ReadPacketAsync(_tcpStream, cancellationToken);
            if (ConnectionInfo.ReadMacAlgorithm.OutputSize != 0)
            {
                var messageAuthenticationHash = await _tcpStream.ReadBytesAsync((uint)ConnectionInfo.ReadMacAlgorithm.OutputSize, cancellationToken);
                if (!ConnectionInfo.ReadMacAlgorithm.VerifyMac(messageAuthenticationHash, ConnectionInfo.InboundPacketSequence, sshPacket))
                {
                    throw new InvalidDataException("Received a malformed packet from host.");
                }
            }

            ConnectionInfo.InboundPacketSequence = ConnectionInfo.InboundPacketSequence != uint.MaxValue ? ConnectionInfo.InboundPacketSequence + 1 : 0;
            var messageEvent = new MessageEvent(sshPacket.Payload);
            _logger.Debug($"{ConnectionInfo.Hostname} - {nameof(ReadMessageAsync)}: Received {messageEvent.Type}");

            // Key Exchange Messages
            switch (messageEvent.Type)
            {
                case MessageType.SSH_MSG_KEXINIT:
                case MessageType.SSH_MSG_NEWKEYS:
                case MessageType.SSH_MSG_KEX_Exchange_30:
                case MessageType.SSH_MSG_KEX_Exchange_31:
                case MessageType.SSH_MSG_KEX_Exchange_32:
                case MessageType.SSH_MSG_KEX_Exchange_33:
                case MessageType.SSH_MSG_KEX_Exchange_34:
                    await ProcessKeyExchangeMessageAsync(messageEvent, cancellationToken);
                    break;
                case MessageType.SSH_MSG_SERVICE_ACCEPT:
                case MessageType.SSH_MSG_REQUEST_FAILURE:
                case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                case MessageType.SSH_MSG_USERAUTH_FAILURE:
                case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                case MessageType.SSH_MSG_USERAUTH_BANNER:
                    await ProcessAuthenticationMessageAsync(messageEvent, cancellationToken);
                    break;
                case MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                case MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE:
                case MessageType.SSH_MSG_CHANNEL_SUCCESS:
                case MessageType.SSH_MSG_CHANNEL_FAILURE:
                case MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                case MessageType.SSH_MSG_CHANNEL_DATA:
                case MessageType.SSH_MSG_CHANNEL_CLOSE:
                case MessageType.SSH_MSG_CHANNEL_EOF:
                    _logger.Debug($"Sending Channel Message to client");
                    await ProcessChannelMessageAsync(messageEvent, cancellationToken);
                    break;
                default:
                    _logger.Info($"{ConnectionInfo.Hostname} - {nameof(ReadMessageAsync)}: Unexpected Message {messageEvent.Type}");
                    break;
            }
        }

        /// <summary>
        /// Forwards a message from the server to the the SshKeyExchange
        /// </summary>
        /// <param name="messageEvent">The message to be processed</param>
        /// <param name="cancellationToken">The cancellation token is used to cancel the process request</param>
        /// <returns></returns>
        private async Task ProcessKeyExchangeMessageAsync(MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            try
            {
                switch (messageEvent.Type)
                {
                    case MessageType.SSH_MSG_KEXINIT:
                        await ConnectionInfo.KeyExchanger.ProcessMessageAsync(messageEvent, cancellationToken);
                        break;
                    case MessageType.SSH_MSG_NEWKEYS:
                        await ConnectionInfo.KeyExchanger.ProcessMessageAsync(messageEvent, cancellationToken);

                        // If we make it to this point without an exception we've successfully completed our key exchange
                        _initialKeyExchangeCompleted?.TrySetResult(true);
                        break;
                    case MessageType.SSH_MSG_KEX_Exchange_30:
                    case MessageType.SSH_MSG_KEX_Exchange_31:
                    case MessageType.SSH_MSG_KEX_Exchange_32:
                    case MessageType.SSH_MSG_KEX_Exchange_33:
                    case MessageType.SSH_MSG_KEX_Exchange_34:
                        await ConnectionInfo.KeyExchanger.ProcessMessageAsync(messageEvent, cancellationToken);
                        break;
                }
            }
            catch (Exception ex)
            {
                _initialKeyExchangeCompleted?.TrySetException(ex);
                throw;
            }
        }

        /// <summary>
        /// Forwards a message from the server to the the SshAuthentication
        /// </summary>
        /// <param name="messageEvent">The message to be processed</param>
        /// <param name="cancellationToken">The cancellation token is used to cancel the process request</param>
        /// <returns></returns>
        private async Task ProcessAuthenticationMessageAsync(MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            try
            {
                switch (messageEvent.Type)
                {
                    case MessageType.SSH_MSG_SERVICE_ACCEPT:
                        await ConnectionInfo.Authentication.ProcessMessageAsync(messageEvent.Message as ServiceAccept, cancellationToken);
                        break;
                    case MessageType.SSH_MSG_REQUEST_FAILURE:
                        await ConnectionInfo.Authentication.ProcessRequestFailureMessage(cancellationToken);
                        break;
                    case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                        await ConnectionInfo.Authentication.ProcessMessageAsync(messageEvent.Message as UaSuccess, cancellationToken);
                        // If we make it to this point with no exceptions we've achieved a success login.
                        _loginCompleted?.TrySetResult(true);
                        break;
                    case MessageType.SSH_MSG_USERAUTH_FAILURE:
                        await ConnectionInfo.Authentication.ProcessMessageAsync(messageEvent.Message as UaFailure, cancellationToken);
                        break;
                    case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                        await ConnectionInfo.Authentication.ProcessMessageAsync(messageEvent.Message as UaInfoRequest, cancellationToken);
                        break;
                    case MessageType.SSH_MSG_USERAUTH_BANNER:
                        Banner = (messageEvent.Message as UaBanner)?.Message;
                        break;
                }
            }
            catch (Exception ex)
            {
                _loginCompleted?.TrySetException(ex);
                throw;
            }
        }

        /// <summary>
        /// Forwards a message from the server to the the SshChannel
        /// </summary>
        /// <param name="messageEvent">The message to be processed</param>
        /// <param name="cancellationToken">The cancellation token is used to cancel the process request</param>
        /// <returns></returns>
        private async Task ProcessChannelMessageAsync(MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            // Runs on background thread
            _logger.Debug($"Checking Channel Message Type");
            if (messageEvent.Message is IChannelRecipient channelMessage)
            {
                await _clientSemaphore.WaitAsync(cancellationToken);
                var channel = _channels.Single(x => x.ClientId == channelMessage.RecipientChannel);
                _clientSemaphore.Release();

                switch (messageEvent.Message)
                {
                    case ChannelSuccess success:
                        await channel.SendMessageAsync(success, cancellationToken);
                        break;
                    case ChannelFailure failure:
                        await channel.SendMessageAsync(failure, cancellationToken);
                        break;
                    case ChannelOpenConfirmation openConfirmation:
                        await channel.SendMessageAsync(openConfirmation, cancellationToken);
                        break;
                    case ChannelOpenFailure openFailure:
                        await channel.SendMessageAsync(openFailure, cancellationToken);
                        break;
                    case ChannelWindowAdjust windowAdjust:
                        await channel.SendMessageAsync(windowAdjust, cancellationToken);
                        break;
                    case ChannelData channelData:
                        await channel.SendMessageAsync(channelData, cancellationToken);
                        break;
                    case ChannelEof channelEof:
                        await channel.SendMessageAsync(channelEof, cancellationToken);
                        break;
                    case ChannelClose channelClose:
                        await channel.SendMessageAsync(channelClose, cancellationToken);
                        break;
                }
            }
        }

        /// <summary>
        /// Writes a message to the server
        /// </summary>
        /// <param name="message">The message to be sent</param>
        /// <param name="cancellationToken">The cancellation token is used to cancel the write message</param>
        /// <returns></returns>
        internal async Task WriteMessageAsync(IMessage message, CancellationToken cancellationToken)
        {
            var compressedPayload = ConnectionInfo.WriteCompressionAlgorithm.Compress(message.GetBytes());
            var sshPacket = new SshPacket(compressedPayload,
                    ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize > 8
                    ? ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize : 8);

            await _tcpStream.WriteAsync(ConnectionInfo.WriteCryptoAlgorithm.Encrypt(sshPacket.Raw), cancellationToken);

            if (ConnectionInfo.WriteMacAlgorithm.OutputSize != 0)
            {
                await _tcpStream.WriteAsync(ConnectionInfo.WriteMacAlgorithm.ComputeHash(ConnectionInfo.OutboundPacketSequence,
                            sshPacket), cancellationToken);
            }

            await _tcpStream.FlushAsync(cancellationToken);
            ConnectionInfo.OutboundPacketSequence = ConnectionInfo.OutboundPacketSequence != uint.MaxValue
                                                         ? ConnectionInfo.OutboundPacketSequence + 1
                                                         : 0;

            _logger.Debug($"{ConnectionInfo.Hostname} - {nameof(WriteMessageAsync)}: Sent {message.Type}");
        }

        /// <summary>
        /// Closes the SshClient
        /// </summary>
        public void Close()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;
                if (!InternalCancellation.IsCancellationRequested)
                {
                    InternalCancellation.Cancel(true);
                }

                foreach (var disposable in _disposables)
                {
                    disposable.Dispose();
                }

                foreach (var channel in _channels)
                {
                    channel.Dispose();
                }

                _sshClientState = State.Closed;
                ConnectionInfo.Authentication?.Dispose();
                InternalCancellation.Dispose();
                _clientSemaphore.Dispose();
                _tcpStream?.Dispose();
                _tcpConnection?.Dispose();
            }
        }

        /// <summary>
        /// Disposes the SshClient
        /// </summary>
        public void Dispose()
        {
            Close();
        }

        /// <summary>
        /// The state the SshClient is in
        /// </summary>
        internal enum State
        {
            Intitial,
            Connecting,
            Connected,
            Closed,
            Error
        }
    }
}
