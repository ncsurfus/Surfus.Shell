using Surfus.Shell.Authentication;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("Surfus.Shell.Tests")]

namespace Surfus.Shell
{
    public record Handler(Predicate<MessageEvent> Filter, Channel<MessageEvent> Channel);

    /// <summary>
    /// SshClient is an SSH client that can be used to connect to an SSH server.
    /// </summary>
    public class SshClient : IAsyncDisposable
    {
        /// <summary>
        /// _sshClientState holds the state of the SshClient.
        /// </summary>
        private State _sshClientState = State.Intitial;

        /// <summary>
        /// _channelCounter holds the current channel index used to derive new channel IDs.
        /// </summary>
        private uint _channelCounter;

        /// <summary>
        /// _channels holds a list of the channels associated to this SshClient.
        /// </summary>
        private readonly Dictionary<uint, SshChannel> _channels = new Dictionary<uint, SshChannel>();

        /// <summary>
        /// _disposables holds a list of the disposable objects.
        /// </summary>
        private readonly List<IDisposable> _disposables = new List<IDisposable>();

        /// <summary>
        /// _isDisposed holds the disposed state of the SshClient.
        /// </summary>
        private bool _isDisposed;

        /// <summary>
        /// Holds the value of us getting a disconnected message or not.
        /// </summary>
        private bool _disconnectReceived;

        /// <summary>
        /// _tcpConnection holds the underlying TCP Connection of the SshClient.
        /// </summary>
        private readonly TcpClient _tcpConnection = new TcpClient();

        /// <summary>
        /// Cancellation Token Source that is cancelled when the client is closing.
        /// </summary>
        private readonly CancellationTokenSource _closeCts = new();

        /// <summary>
        /// _tcpStream holds the underlying NetworkStream of the TCP Connection.
        /// </summary>
        private NetworkStream _tcpStream;

        private readonly object _handlerLock = new();
        private ImmutableList<Handler> _handlers = ImmutableList.Create<Handler>();

        /// <summary>
        /// A task that reads messages from the incoming SSH server.
        /// </summary>
        private Task _readLoop;

        /// <summary>
        /// A semaphore that coordinates messages being sent to the SSH server.
        /// </summary>
        private readonly SemaphoreSlim _writeSemaphore = new(1, 1);

        private Task _currentKeyExchange = null;

        /// <summary>
        /// IsConnected determines if the SshClient is connected to the remote SSH server.
        /// </summary>
        public bool IsConnected =>
            _tcpConnection?.Connected == true && !_disconnectReceived && !_isDisposed && _sshClientState == State.Authenticated;

        /// <summary>
        /// ConnectionInfo contains connection information of the SshClient.
        /// </summary>
        public SshConnectionInfo ConnectionInfo = new SshConnectionInfo();

        /// <summary>
        /// Banner holds the banner message sent by the SSH server after login. If null, no banner was sent.
        /// </summary>
        public string Banner { get; private set; }

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
        /// ConnectAsync connects to the SSH server.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            // Validate current state of SshClient
            if (_sshClientState != State.Intitial)
            {
                ThrowOnInvalidState();
            }

            // Set new state of SshClient
            _sshClientState = State.Connecting;

            // Set SshClient defaults
            // TODO just set these in the constructor?
            ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
            ConnectionInfo.Authentication = new SshAuthentication(this);

            // Perform version exchange and key exchange
            ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken).ConfigureAwait(false);

            // Start Key Exchange
            _currentKeyExchange = ConnectionInfo.KeyExchanger.StartKeyExchangeAsync(cancellationToken);
            var currentKeyExchange = _currentKeyExchange;

            // Start the read loop
            async Task readLoop()
            {
                async Task readLoopAsync()
                {
                    try
                    {
                        while (true)
                        {
                            await ReadMessageAsync(_closeCts.Token);
                        }
                    }
                    catch (Exception ex)
                    {
                        CleanupHandlers(ex);
                    }
                    finally
                    {
                        CleanupHandlers(null);
                    }
                }
                await readLoopAsync();
                _closeCts.Cancel();
            }
            _readLoop = readLoop();

            await currentKeyExchange.ConfigureAwait(false);
            _sshClientState = State.Authenticating;
        }

        /// <summary>
        /// AuthenticateAsync authenticates to the SSH server with the specific username and password.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="password">The password to login with</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task<bool> AuthenticateAsync(string username, string password, CancellationToken cancellationToken)
        {
            var handler = new PasswordAuthenticationHandler(this, username, password);
            var result = await ConnectionInfo.Authentication.LoginAsync(handler, cancellationToken).ConfigureAwait(false);
            if (result)
            {
                _sshClientState = State.Authenticated;
            }
            return result;
        }

        /// <summary>
        /// AuthenticateAsync authenticates to the SSH server with the specific username and interactive login callback.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="interactiveCallback">interactiveCallback is a callback to a method for interactive login</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task<bool> AuthenticateAsync(
            string username,
            InteractiveCallback interactiveCallback,
            CancellationToken cancellationToken
        )
        {
            var handler = new InteractiveAuthenticationHandler(this, username, interactiveCallback);
            var result = await ConnectionInfo.Authentication.LoginAsync(handler, cancellationToken).ConfigureAwait(false);
            if (result)
            {
                _sshClientState = State.Authenticated;
            }
            return result;
        }

        /// <summary>
        /// Requests a terminal from the SSH server.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the terminal request</param>
        /// <returns>A task representing the state of the terminal request</returns>
        internal async Task<SshTerminal> CreateTerminalAsync(CancellationToken cancellationToken)
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
                    throw new OperationCanceledException("The operation was cancelled during the TCP connect.", cancellationToken);
                }

                await connectTask.ConfigureAwait(false);

                // Attempt to get version..
                _tcpStream = _tcpConnection.GetStream();

                // Buffer to receive their version.
                var buffer = new byte[255];
                var bufferPosition = 0;
                var ignoreText = false;
                var readingVersion = false;

                while (bufferPosition == 0 || buffer[bufferPosition - 1] != '\n')
                {
                    if (bufferPosition == buffer.Length)
                    {
                        throw new SshException($"Failed to exchange SSH version. Version size is greater than {buffer.Length}.");
                    }

                    // It appears in some cases ReadAsync can get hung and not properly respond to the CancellationToken.
                    var readTask = _tcpStream.ReadAsync(buffer, bufferPosition, buffer.Length - bufferPosition, cancellationToken);
                    var readResult = await Task.WhenAny(timeout.Task, readTask).ConfigureAwait(false);

                    if (readResult == timeout.Task)
                    {
                        throw new OperationCanceledException(
                            "The operation was cancelled when reading the server version.",
                            cancellationToken
                        );
                    }

                    var readAmount = await readTask.ConfigureAwait(false);

                    if (readAmount <= 0)
                    {
                        if (bufferPosition == 0)
                        {
                            throw new SshException("Failed to exchange SSH version. No data was sent.");
                        }
                        throw new SshException("Failed to exchange SSH version. Connection was closed.");
                    }

                    if (readingVersion || bufferPosition + readAmount < 4)
                    {
                        // We either already found the version or we don't have enough data to do any processing. Either way read the data and loop.
                        bufferPosition += readAmount;
                    }
                    else if (!ignoreText && buffer[0] == 'S' && buffer[1] == 'S' && buffer[2] == 'H' && buffer[3] == '-')
                    {
                        // We found the SSH version! Hooray.
                        bufferPosition += readAmount;
                        readingVersion = true;
                    }
                    else
                    {
                        ignoreText = true;
                        for (var i = 0; i != bufferPosition + readAmount; i++)
                        {
                            if (buffer[i] == '\n')
                            {
                                // Realign the buffer
                                for (var j = 0; j != bufferPosition + readAmount - i - 1; j++)
                                {
                                    buffer[j] = buffer[i + j + 1];
                                }
                                bufferPosition = bufferPosition - i + readAmount - 1;
                                readAmount = 0;

                                // Check for version
                                if (bufferPosition > 4 && buffer[0] == 'S' && buffer[1] == 'S' && buffer[2] == 'H' && buffer[3] == '-')
                                {
                                    readingVersion = true;
                                    i = bufferPosition + readAmount - 1;
                                }
                                else
                                {
                                    i = -1;
                                }
                            }
                        }

                        // We never matched on any data. Reset buffer.
                        if (!readingVersion)
                        {
                            bufferPosition = 0;
                        }
                    }
                }

                var version =
                    buffer[bufferPosition - 2] == '\r'
                        ? Encoding.ASCII.GetString(buffer, 0, bufferPosition - 2)
                        : Encoding.ASCII.GetString(buffer, 0, bufferPosition - 1);
                if (!version.StartsWith("SSH-1.99-") && !version.StartsWith("SSH-2.0-"))
                {
                    throw new SshException("Server version is not supported.");
                }
                var clientVersionBytes = Encoding.UTF8.GetBytes(ConnectionInfo.ClientVersion + "\n");
                await _tcpStream.WriteAsync(clientVersionBytes, 0, clientVersionBytes.Length, cancellationToken).ConfigureAwait(false);
                await _tcpStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                return version;
            }
        }

        /// <summary>
        /// Reads a message from the server
        /// </summary>
        /// <param name="cancellationToken">The cancellation token is used to cancel the ReadMessage request</param>
        /// <returns></returns>
        private async Task ReadMessageAsync(CancellationToken cancellationToken)
        {
            var sshPacketTask = ConnectionInfo.ReadCryptoAlgorithm.ReadPacketAsync(
                _tcpStream,
                ConnectionInfo.InboundPacketSequence,
                ConnectionInfo.ReadMacAlgorithm.OutputSize,
                cancellationToken
            );

            var sshPacket = await sshPacketTask.ConfigureAwait(false);

            if (ConnectionInfo.ReadMacAlgorithm.OutputSize != 0)
            {
                if (!ConnectionInfo.ReadMacAlgorithm.VerifyMac(ConnectionInfo.InboundPacketSequence, sshPacket))
                {
                    throw new SshException("The server sent a malformed message.");
                }
            }

            ConnectionInfo.InboundPacketSequence =
                ConnectionInfo.InboundPacketSequence != uint.MaxValue ? ConnectionInfo.InboundPacketSequence + 1 : 0;
            var messageEvent = new MessageEvent(sshPacket);

            // Key Exchange Messages
            switch (messageEvent.Type)
            {
                case MessageType.SSH_MSG_DISCONNECT:
                    _disconnectReceived = true;
                    break;
            }

            if (ConnectionInfo.KeyExchanger.IsKeyExchangeStart(messageEvent))
            {
                if (_currentKeyExchange == null)
                {
                    _currentKeyExchange = Task.Run(() => ConnectionInfo.KeyExchanger.StartKeyExchangeAsync(cancellationToken));
                }
            }

            foreach (var handler in _handlers)
            {
                if (handler.Filter(messageEvent))
                {
                    await handler.Channel.Writer.WriteAsync(messageEvent, cancellationToken).ConfigureAwait(false);
                }
            }

            if (ConnectionInfo.KeyExchanger.IsKeyExchangeEnd(messageEvent))
            {
                if (_currentKeyExchange == null)
                {
                    throw new Exception("Received end of key exchange, but key exchange not in progress!");
                }
                await _currentKeyExchange.ConfigureAwait(false);
                _currentKeyExchange = null;
            }
        }

        internal ChannelReader<MessageEvent> RegisterMessageHandler(Predicate<MessageEvent> filter, int capacity = 1)
        {
            var channel = Channel.CreateBounded<MessageEvent>(capacity);
            lock (_handlerLock)
            {
                // Check if closed?
                _handlers = _handlers.Add(new Handler(filter, channel));
            }
            return channel.Reader;
        }

        internal void DeregisterMessageHandler(ChannelReader<MessageEvent> channelReader)
        {
            lock (_handlerLock)
            {
                foreach (var handler in _handlers)
                {
                    if (handler.Channel.Reader == channelReader)
                    {
                        _handlers = _handlers.Remove(handler);
                    }
                    return;
                }
            }
        }

        internal void CleanupHandlers(Exception ex)
        {
            lock (_handlers)
            {
                foreach (var handler in _handlers)
                {
                    handler.Channel.Writer.Complete(ex);
                }
                _handlers = _handlers.Clear();
                _sshClientState = State.Error;
            }
        }

        /// <summary>
        /// Writes a message to the server
        /// </summary>
        /// <param name="message">The message to be sent</param>
        /// <param name="cancellationToken">The cancellation token is used to cancel the write message</param>
        /// <returns></returns>
        internal async Task WriteMessageAsync(IClientMessage message, CancellationToken cancellationToken)
        {
            if (message is NewKeysComplete)
            {
                _writeSemaphore.Release();
                return;
            }

            await _writeSemaphore.WaitAsync(cancellationToken);
            try
            {
                // TODO: Fix compressedPayload! var compressedPayload = ConnectionInfo.WriteCompressionAlgorithm.Compress(message.GetBytes());
                // We don't actually support compression though... so no rush...
                var sshPacket = new SshPacket(message.GetByteWriter(), Math.Max(ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize, 8));
                ByteWriter.WriteUint(sshPacket.Buffer, SshPacket.SequenceIndex, ConnectionInfo.OutboundPacketSequence);
                byte[] macOutput = ConnectionInfo.WriteMacAlgorithm.ComputeHash(ConnectionInfo.OutboundPacketSequence, sshPacket);

                ConnectionInfo.WriteCryptoAlgorithm.Encrypt(sshPacket.Buffer, sshPacket.Offset, sshPacket.Length);
                await _tcpStream.WriteAsync(sshPacket.Buffer, sshPacket.Offset, sshPacket.Length, cancellationToken).ConfigureAwait(false);

                if (ConnectionInfo.WriteMacAlgorithm.OutputSize != 0)
                {
                    await _tcpStream
                        .WriteAsync(macOutput, 0, ConnectionInfo.WriteMacAlgorithm.OutputSize, cancellationToken)
                        .ConfigureAwait(false);
                }

                await _tcpStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                ConnectionInfo.OutboundPacketSequence =
                    ConnectionInfo.OutboundPacketSequence != uint.MaxValue ? ConnectionInfo.OutboundPacketSequence + 1 : 0;
            }
            finally
            {
                if (message is not NewKeys)
                {
                    _writeSemaphore.Release();
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
                ConnectionInfo.Dispose();
                _tcpStream?.Dispose();
                _tcpConnection?.Dispose();
            }
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
                    throw new SshException($"The {nameof(SshClient)} is already attempting a connection.");
                case State.Authenticated:
                    throw new SshException($"The {nameof(SshClient)} is already connected.");
                case State.Error:
                    throw new SshException($"The {nameof(SshClient)} had a fatal error.");
                case State.Closed:
                    throw new SshException($"The {nameof(SshClient)} has disconnected.");
                default:
                    throw new SshException($"The {nameof(SshClient)} had an unknown error.");
            }
        }

        public async ValueTask DisposeAsync()
        {
            _closeCts.Cancel();
            Close();
            try
            {
                if (_readLoop != null)
                {
                    await _readLoop;
                }
            }
            catch (Exception) { }
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
