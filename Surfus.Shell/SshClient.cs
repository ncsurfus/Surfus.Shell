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
        /// _sshClientState holds the state of the SshClient.
        /// </summary>
        private State _sshClientState = State.Intitial;

        /// <summary>
        /// _channelCounter holds the current channel index used to derive new channel IDs.
        /// </summary>
        private uint _channelCounter = 0;

        /// <summary>
        /// _channels holds a list of the channels associated to this SshClient.
        /// </summary>
        private Dictionary<uint, SshChannel> _channels = new Dictionary<uint, SshChannel>();

        /// <summary>
        /// _disposables holds a list of the disposable objects.
        /// </summary>
        private List<IDisposable> _disposables = new List<IDisposable>();

        /// <summary>
        /// _isDisposed holds the disposed state of the SshClient.
        /// </summary>
        private bool _isDisposed = false;

        /// <summary>
        /// Holds the value of us getting a disconnected message or not.
        /// </summary>
        private bool _disconnectReceived = false;

        /// <summary>
        /// _tcpConnection holds the underlying TCP Connection of the SshClient.
        /// </summary>
        private TcpClient _tcpConnection = new TcpClient();

        /// <summary>
        /// _tcpStream holds the underlying NetworkStream of the TCP Connection.
        /// </summary>
        private NetworkStream _tcpStream;

        /// <summary>
        /// IsConnected determines if the SshClient is connected to the remote SSH server.
        /// </summary>
        public bool IsConnected => _tcpConnection?.Connected == true && !_disconnectReceived && !_isDisposed && _sshClientState == State.Authenticated;

        /// <summary>
        /// IsConnecting determines if the SshClient is connecting to the remote SSH server.
        /// </summary>
        private bool _isConnecting => _tcpConnection?.Connected == true && !_disconnectReceived && !_isDisposed && (_sshClientState == State.Connecting || _sshClientState == State.Connected || _sshClientState == State.Authenticating);

        /// <summary>
        /// ConnectionInfo contains connection information of the SshClient.
        /// </summary>
        public SshConnectionInfo ConnectionInfo = new SshConnectionInfo();

        /// <summary>
        /// Banner holds the banner message sent by the SSH server after login. If null, no banner was sent.
        /// </summary>
        public string Banner { get; private set; } = null;

        /// <summary>
        /// When set, calls this callback function to determine if the host key is valid and if the connection should continue.
        /// </summary>
        public Func<byte[], bool> HostKeyCallback = null;

        /// <summary>
        /// An SshClient that can connect designated hostname and port.
        /// </summary>
        /// <param name="hostname">The remote SSH Server.</param>
        /// <param name="port">The remote SSH port.</param>
        public SshClient(string hostname, ushort port = 22)
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
            // Validate current state of SshClient
            if (_sshClientState != State.Intitial)
            {
                ThrowOnInvalidState();
            }

            // Set new state of SshClient
            _sshClientState = State.Connecting;

            // Set SshClient defaults
            ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
            ConnectionInfo.Authentication = new SshAuthentication(this);

            // Perform version exchange and key exchange
            ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken).ConfigureAwait(false);
            await ConnectionInfo.KeyExchanger.AwaitKeyExchangeAsync(cancellationToken).ConfigureAwait(false);
            await ConnectionInfo.Authentication.LoginAsync(username, password, cancellationToken).ConfigureAwait(false);
            _sshClientState = State.Authenticated;
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
            // Validate current state of SshClient
            if (_sshClientState != State.Intitial)
            {
                ThrowOnInvalidState();
            }

            // Set new state of SshClient
            _sshClientState = State.Connecting;

            // Set SshClient defaults
            ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
            ConnectionInfo.Authentication = new SshAuthentication(this);

            // Perform version exchange and key exchange
            ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken).ConfigureAwait(false);
            await ConnectionInfo.KeyExchanger.AwaitKeyExchangeAsync(cancellationToken).ConfigureAwait(false);
            await ConnectionInfo.Authentication.LoginAsync(username, interactiveResponse, cancellationToken).ConfigureAwait(false);
            _sshClientState = State.Authenticated;
        }

        /// <summary>
        /// ConnectAsync connects to the SSH server with the specific username and password.
        /// </summary>
        /// <param name="hostname">The host to connect to</param>
        /// <param name="username">The username to login as</param>
        /// <param name="password">The password to login with</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public static async Task<SshClient> ConnectAsync(string hostname, string username, string password, CancellationToken cancellationToken)
        {
            var sshClient = new SshClient(hostname);
            await sshClient.ConnectAsync(username, password, cancellationToken);
            return sshClient;
        }

        /// <summary>
        /// ConnectAsync connects to the SSH server with the specific username and interactive login callback.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="hostname">The host to connect to</param>
        /// <param name="interactiveResponse">interactiveResponse is a callback to a method for interactive login</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public static async Task<SshClient> ConnectAsync(string hostname, string username, Func<string, CancellationToken, Task<string>> interactiveResponse, CancellationToken cancellationToken)
        {
            var sshClient = new SshClient(hostname);
            await sshClient.ConnectAsync(username, interactiveResponse, cancellationToken);
            return sshClient;
        }

        /// <summary>
        /// ConnectAsync connects to the SSH server with the specific username and password.
        /// </summary>
        /// <param name="hostname">The host to connect to</param>
        /// <param name="port">The port to connect to</param>
        /// <param name="username">The username to login as</param>
        /// <param name="password">The password to login with</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public static async Task<SshClient> ConnectAsync(string hostname, uint port, string username, string password, CancellationToken cancellationToken)
        {
            var sshClient = new SshClient(hostname);
            await sshClient.ConnectAsync(username, password, cancellationToken);
            return sshClient;
        }

        /// <summary>
        /// ConnectAsync connects to the SSH server with the specific username and interactive login callback.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="port">The port to connect to</param>
        /// <param name="hostname">The host to connect to</param>
        /// <param name="interactiveResponse">interactiveResponse is a callback to a method for interactive login</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public static async Task<SshClient> ConnectAsync(string hostname, uint port, string username, Func<string, CancellationToken, Task<string>> interactiveResponse, CancellationToken cancellationToken)
        {
            var sshClient = new SshClient(hostname);
            await sshClient.ConnectAsync(username, interactiveResponse, cancellationToken);
            return sshClient;
        }

        /// <summary>
        /// Requests a terminal from the SSH server.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the terminal request</param>
        /// <returns>A task representing the state of the terminal request</returns>
        public async Task<SshTerminal> CreateTerminalAsync(CancellationToken cancellationToken)
        {
            // Validate current state of SshClient
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            // Setup the new terminal
            var channel = new SshChannel(this, _channelCounter);
            var terminal = new SshTerminal(this, channel);

            _channels[_channelCounter] = channel;
            _disposables.Add(terminal);
            _channelCounter++;

            await terminal.OpenAsync(cancellationToken).ConfigureAwait(false);
            return terminal;
        }

        /// <summary>
        /// Requests the result of a command from the SSH server.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the terminal request</param>
        /// <returns>A task representing the state of the terminal request</returns>
        public async Task<SshCommand> CreateCommandAsync(CancellationToken cancellationToken)
        {
            // Validate current state of SshClient
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            // Setup the new terminal
            var channel = new SshChannel(this, _channelCounter);
            var command = new SshCommand(this, channel);

            _channels[_channelCounter] = channel;
            _disposables.Add(command);
            _channelCounter++;

            await command.OpenAsync(cancellationToken).ConfigureAwait(false);
            return command;
        }

        /// <summary>
        /// Initiates the SSH connection by exchanging versions.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token used to cancel the version exchange.</param>
        /// <returns>A task representing the state of the version exchange</returns>
        private async Task<string> ExchangeVersionAsync(CancellationToken cancellationToken)
        {
            // A cancellation token cannot be pased to the TcpClient.ConnectAsync, you *must* rely on the timeout. This is a work-around.
            var timeout = new TaskCompletionSource<bool>();
            using (cancellationToken.Register(() => timeout.SetResult(true)))
            {
                var connectTask = _tcpConnection.ConnectAsync(ConnectionInfo.Hostname, ConnectionInfo.Port);
                var connectResult = await Task.WhenAny(timeout.Task, connectTask).ConfigureAwait(false);

                if (connectResult == timeout.Task)
                {
                    throw new SshException("Cancellation exception thrown during TCP Connect.", new TaskCanceledException());
                }

                await connectTask.ConfigureAwait(false);

                // Attempt to get version..
                _tcpStream = _tcpConnection.GetStream();

                // Buffer to receive their version.
                var buffer = new byte[ushort.MaxValue];
                var bufferPosition = 0;

                while (bufferPosition == 0 || buffer[bufferPosition - 1] != '\n')
                {
                    if (bufferPosition == ushort.MaxValue)
                    {
                        throw new SshException($"Failed to exchange SSH version. Version size is greater than {ushort.MaxValue}.");
                    }

                    // It appears in some cases ReadAsync can get hung and not properly respond to the CancellationToken.
                    var readTask = _tcpStream.ReadAsync(buffer, bufferPosition, ushort.MaxValue - bufferPosition, cancellationToken);
                    var readResult = await Task.WhenAny(timeout.Task, readTask).ConfigureAwait(false);

                    if (readResult == timeout.Task)
                    {
                        throw new SshException("Failed to exchange SSH version. Cancellation exception thrown during TCP Read.", new TaskCanceledException());
                    }

                    var readAmount = await readTask.ConfigureAwait(false);

                    if (readAmount <= 0)
                    {
                        if (bufferPosition == 0)
                        {
                            throw new SshException($"Failed to exchange SSH version. No data was sent.");
                        }
                        throw new SshException($"Failed to exchange SSH version. Connection was closed.");
                    }

                    bufferPosition += readAmount;
                }

                var versionMatch = Regex.Match(Encoding.UTF8.GetString(buffer, 0, bufferPosition), @"^SSH-(?<ProtoVersion>\d\.\d+)-(?<SoftwareVersion>\S+)(?<Comments>\s[^\r\n]+)?((?=\r\n$)|(?=\n$))");

                if (versionMatch.Success && (versionMatch.Groups["ProtoVersion"].Value == "2.0" || versionMatch.Groups["ProtoVersion"].Value == "1.99"))
                {
                    var clientVersionBytes = Encoding.UTF8.GetBytes(ConnectionInfo.ClientVersion + "\n");
                    await _tcpStream.WriteAsync(clientVersionBytes, 0, clientVersionBytes.Length, cancellationToken).ConfigureAwait(false);
                    await _tcpStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                    return versionMatch.Value;
                }
                else if(versionMatch.Success)
                {
                    throw new SshException($"Failed to exchange SSH Version. Version {versionMatch.Value} is not supported.");
                }

                throw new SshException($"Failed to exchange SSH Version. The server sent the version in an invalid format.");
            }
        }

        /// <summary>
        /// Reads packets from the server until the callback method returns true.
        /// </summary>
        /// <returns></returns>
        internal async Task ReadUntilAsync(Func<bool> method, CancellationToken cancellationToken)
        {
            while (!method())
            {
                await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Reads packets from the server until the callback method returns true.
        /// </summary>
        /// <returns></returns>
        internal async Task ReadUntilAsync(Func<Task<bool>> method, CancellationToken cancellationToken)
        {
            while (!await method())
            {
                await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Reads a message from the server
        /// </summary>
        /// <param name="cancellationToken">The cancellation token is used to cancel the ReadMessage request</param>
        /// <returns></returns>
        private async Task ReadMessageAsync(CancellationToken cancellationToken)
        {
            var cancelRead = new TaskCompletionSource<bool>();
            using (cancellationToken.Register(() => cancelRead.SetResult(true)))
            {
                var sshPacketTask = ConnectionInfo.ReadCryptoAlgorithm.ReadPacketAsync(_tcpStream, cancellationToken);
                var readPacket = await Task.WhenAny(cancelRead.Task, sshPacketTask).ConfigureAwait(false);

                if(readPacket == cancelRead.Task)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new SshException("CancellationToken was triggered, but did not throw a cancel exception. This should not happen.");
                }

                var sshPacket = await sshPacketTask.ConfigureAwait(false);

                if (ConnectionInfo.ReadMacAlgorithm.OutputSize != 0)
                {
                    var messageAuthenticationHash = await _tcpStream.ReadBytesAsync((uint)ConnectionInfo.ReadMacAlgorithm.OutputSize, cancellationToken).ConfigureAwait(false);
                    if (!ConnectionInfo.ReadMacAlgorithm.VerifyMac(messageAuthenticationHash, ConnectionInfo.InboundPacketSequence, sshPacket))
                    {
                        throw new InvalidDataException("Received a malformed packet from host.");
                    }
                }

                ConnectionInfo.InboundPacketSequence = ConnectionInfo.InboundPacketSequence != uint.MaxValue ? ConnectionInfo.InboundPacketSequence + 1 : 0;
                var messageEvent = new MessageEvent(sshPacket.Payload);

                // Key Exchange Messages
                switch (messageEvent.Type)
                {
                    case MessageType.SSH_MSG_DISCONNECT:
                        _disconnectReceived = true;
                        break;
                    case MessageType.SSH_MSG_KEXINIT:
                    case MessageType.SSH_MSG_NEWKEYS:
                    case MessageType.SSH_MSG_KEX_Exchange_30:
                    case MessageType.SSH_MSG_KEX_Exchange_31:
                    case MessageType.SSH_MSG_KEX_Exchange_32:
                    case MessageType.SSH_MSG_KEX_Exchange_33:
                    case MessageType.SSH_MSG_KEX_Exchange_34:
                        await ProcessKeyExchangeMessageAsync(messageEvent, cancellationToken).ConfigureAwait(false);
                        break;
                    case MessageType.SSH_MSG_SERVICE_ACCEPT:
                    case MessageType.SSH_MSG_REQUEST_FAILURE:
                    case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                    case MessageType.SSH_MSG_USERAUTH_FAILURE:
                    case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                    case MessageType.SSH_MSG_USERAUTH_BANNER:
                        await ProcessAuthenticationMessageAsync(messageEvent, cancellationToken).ConfigureAwait(false);
                        break;
                    case MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                    case MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE:
                    case MessageType.SSH_MSG_CHANNEL_SUCCESS:
                    case MessageType.SSH_MSG_CHANNEL_FAILURE:
                    case MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                    case MessageType.SSH_MSG_CHANNEL_DATA:
                    case MessageType.SSH_MSG_CHANNEL_CLOSE:
                    case MessageType.SSH_MSG_CHANNEL_EOF:
                        await ProcessChannelMessageAsync(messageEvent, cancellationToken).ConfigureAwait(false);
                        break;
                    default:
                        break;
                }
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
            switch (messageEvent.Type)
            {
                case MessageType.SSH_MSG_KEXINIT:
                    await ConnectionInfo.KeyExchanger.ProcessMessageAsync(messageEvent, cancellationToken).ConfigureAwait(false);
                    break;
                case MessageType.SSH_MSG_NEWKEYS:
                    await ConnectionInfo.KeyExchanger.ProcessMessageAsync(messageEvent, cancellationToken).ConfigureAwait(false);
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_30:
                case MessageType.SSH_MSG_KEX_Exchange_31:
                case MessageType.SSH_MSG_KEX_Exchange_32:
                case MessageType.SSH_MSG_KEX_Exchange_33:
                case MessageType.SSH_MSG_KEX_Exchange_34:
                    await ConnectionInfo.KeyExchanger.ProcessMessageAsync(messageEvent, cancellationToken).ConfigureAwait(false);
                    break;
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
            switch (messageEvent.Type)
            {
                case MessageType.SSH_MSG_SERVICE_ACCEPT:
                    await ConnectionInfo.Authentication.ProcessMessageAsync(messageEvent.Message as ServiceAccept, cancellationToken).ConfigureAwait(false);
                    break;
                case MessageType.SSH_MSG_REQUEST_FAILURE:
                    ConnectionInfo.Authentication.ProcessRequestFailureMessage();
                    break;
                case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                    ConnectionInfo.Authentication.ProcessMessageAsync(messageEvent.Message as UaSuccess);
                    break;
                case MessageType.SSH_MSG_USERAUTH_FAILURE:
                    ConnectionInfo.Authentication.ProcessMessageAsync(messageEvent.Message as UaFailure);
                    break;
                case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                    await ConnectionInfo.Authentication.ProcessMessageAsync(messageEvent.Message as UaInfoRequest, cancellationToken).ConfigureAwait(false);
                    break;
                case MessageType.SSH_MSG_USERAUTH_BANNER:
                    Banner = (messageEvent.Message as UaBanner)?.Message;
                    break;
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
            if (messageEvent.Message is IChannelRecipient channelMessage)
            {
               if(!_channels.ContainsKey(channelMessage.RecipientChannel))
                {
                    throw new SshException("Server sent a message for a invalid recipient channel.");
                }

                var channel = _channels[channelMessage.RecipientChannel];

                switch (messageEvent.Message)
                {
                    case ChannelSuccess success:
                        channel.ProcessMessageAsync(success);
                        break;
                    case ChannelFailure failure:
                        channel.ProcessMessageAsync(failure);
                        break;
                    case ChannelOpenConfirmation openConfirmation:
                        channel.ProcessMessageAsync(openConfirmation);
                        break;
                    case ChannelOpenFailure openFailure:
                        channel.ProcessMessageAsync(openFailure);
                        break;
                    case ChannelWindowAdjust windowAdjust:
                        channel.ProcessMessageAsync(windowAdjust);
                        break;
                    case ChannelData channelData:
                        await channel.ProcessMessageAsync(channelData, cancellationToken).ConfigureAwait(false);
                        break;
                    case ChannelEof channelEof:
                        channel.ProcessMessageAsync(channelEof);
                        break;
                    case ChannelClose channelClose:
                        channel.ProcessMessageAsync(channelClose);
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

            await _tcpStream.WriteAsync(ConnectionInfo.WriteCryptoAlgorithm.Encrypt(sshPacket.Raw), cancellationToken).ConfigureAwait(false);

            if (ConnectionInfo.WriteMacAlgorithm.OutputSize != 0)
            {
                await _tcpStream.WriteAsync(ConnectionInfo.WriteMacAlgorithm.ComputeHash(ConnectionInfo.OutboundPacketSequence,
                            sshPacket), cancellationToken).ConfigureAwait(false);
            }

            await _tcpStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            ConnectionInfo.OutboundPacketSequence = ConnectionInfo.OutboundPacketSequence != uint.MaxValue
                                                         ? ConnectionInfo.OutboundPacketSequence + 1
                                                         : 0;
        }

        /// <summary>
        /// Processes packets in the background until the connection has been disconnected.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task ProcessPacketsAsync(CancellationToken cancellationToken)
        {
            await ReadUntilAsync(() => !IsConnected, cancellationToken);
        }

        /// <summary>
        /// Processes packets in the background until the condition has been met.
        /// </summary>
        /// <param name="condition">The condition that must be true to exit the method.</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task ProcessPacketsAsync(Func<bool> untilCondition, CancellationToken cancellationToken)
        {
            await ReadUntilAsync(untilCondition, cancellationToken);
        }

        /// <summary>
        /// Processes packets in the background until the condition has been met.
        /// </summary>
        /// <param name="condition">The condition that must be true to exit the method.</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task ProcessPacketsAsync(Func<Task<bool>> untilCondition, CancellationToken cancellationToken)
        {
            await ReadUntilAsync(untilCondition, cancellationToken);
        }

        /// <summary>
        /// Processes packets in the background for the specified amount of time.
        /// </summary>
        /// <param name="timeSpan">The amount of time to wait.</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task ProcessPacketsAsync(TimeSpan timeSpan, CancellationToken cancellationToken)
        {
            var taskTimer = Task.Delay(timeSpan, cancellationToken);
            await ReadUntilAsync(() => taskTimer.IsCompleted, cancellationToken);
            await taskTimer;
        }

        /// <summary>
        /// Processes packets in the background for the specified amount of milliseconds..
        /// </summary>
        /// <param name="milliseconds">The amount of milliseconds to wait for.</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task ProcessPacketsAsync(int milliseconds, CancellationToken cancellationToken)
        {
            var taskTimer = Task.Delay(milliseconds, cancellationToken);
            await ReadUntilAsync(() => taskTimer.IsCompleted, cancellationToken);
            await taskTimer;
        }

        /// <summary>
        /// Continues to process packets until there are no incoming packets left.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        internal async Task ProcessAdditionalAsync(int delay, CancellationToken cancellationToken)
        {
            if (!_tcpStream.DataAvailable)
            {
                await Task.Delay(delay).ConfigureAwait(false);
            }

            while (_tcpStream.DataAvailable)
            {
                await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                if (!_tcpStream.DataAvailable)
                {
                    await Task.Delay(delay).ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// Closes the SshClient
        /// </summary>
        public void Close()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;

                foreach (var disposable in _disposables)
                {
                    disposable.Dispose();
                }

                _sshClientState = State.Closed;
                ConnectionInfo.Authentication?.Dispose();
                ConnectionInfo.Dispose();
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
        /// Throws an SshException if the SshClient is in an invalid state to continue.
        /// </summary>
        private void ThrowOnInvalidState()
        {
            switch (_sshClientState)
            {
                case State.Connecting:
                case State.Connected:
                case State.Authenticating:
                    throw new SshException($"The Connection is already in progress. Did you try to connect twice?");
                case State.Authenticated:
                    throw new SshException($"The Connection is already connected. Did you try to connect twice?");
                case State.Error:
                case State.Closed:
                    throw new SshException($"The Connection had an error and could not continue.");
                default:
                    throw new SshException($"The connection had an unknown error and could not continue.");
            }
        }

        /// <summary>
        /// The state the SshClient is in
        /// </summary>
        internal enum State
        {
            Intitial,
            Connecting,
            Connected,
            Authenticating,
            Authenticated,
            Closed,
            Error
        }
    }
}
