using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Authentication;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using Surfus.Shell.Messages.UserAuth;

[assembly: InternalsVisibleTo("Surfus.Shell.Tests")]

namespace Surfus.Shell
{
    /// <summary>
    /// SshClient is an SSH client that can be used to connect to an SSH server.
    /// </summary>
    public class SshClient : IAsyncDisposable
    {
        /// <summary>
        /// _sshClientState holds the state of the SshClient.
        /// </summary>
        private volatile State _sshClientState = State.Initial;

        /// <summary>
        /// _channelCounter holds the current channel index used to derive new channel IDs.
        /// Interlocked.Increment returns the incremented value, so IDs start at 1. This is
        /// intentional — SSH does not require channel 0 and starting at 1 is valid.
        /// </summary>
        private int _channelCounter;

        /// <summary>
        /// _disposables holds a list of the disposable objects.
        /// </summary>
        private readonly List<IAsyncDisposable> _disposables = new List<IAsyncDisposable>();

        /// <summary>
        /// _isDisposed holds the disposed state of the SshClient.
        /// </summary>
        private int _isDisposed;

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

        private readonly object _handlersLock = new();
        private ImmutableList<IMessageHandler> _messageHandlers = ImmutableList.Create<IMessageHandler>();

        /// <summary>
        /// Registers a message handler. Automatically wires OnSend to WriteMessageAsync.
        /// Returns a disposable that unregisters it.
        /// </summary>
        internal IDisposable RegisterMessageHandler(IMessageHandler handler)
        {
            handler.OnSend = WriteMessageAsync;
            lock (_handlersLock)
            {
                _messageHandlers = _messageHandlers.Add(handler);
            }
            return new HandlerRegistration(this, handler);
        }

        private void UnregisterMessageHandler(IMessageHandler handler)
        {
            lock (_handlersLock)
            {
                _messageHandlers = _messageHandlers.Remove(handler);
            }
        }

        private void NotifyHandlersOfError(Exception error)
        {
            var handlers = _messageHandlers;
            foreach (var handler in handlers)
                handler.OnError(error);
        }

        private sealed class HandlerRegistration : IDisposable, IAsyncDisposable
        {
            private readonly SshClient _client;
            private readonly IMessageHandler _handler;

            public HandlerRegistration(SshClient client, IMessageHandler handler)
            {
                _client = client;
                _handler = handler;
            }

            public void Dispose() => _client.UnregisterMessageHandler(_handler);

            public ValueTask DisposeAsync()
            {
                Dispose();
                return default;
            }
        }

        /// <summary>
        /// A task that reads messages from the incoming SSH server.
        /// </summary>
        private Task _readLoop;

        /// <summary>
        /// A semaphore that coordinates messages being sent to the SSH server.
        /// </summary>
        private readonly SemaphoreSlim _writeSemaphore = new(1, 1);

        /// <summary>
        /// IsConnected determines if the SshClient is connected to the remote SSH server.
        /// Note: This is best-effort and subject to TOCTOU races inherent to network programming.
        /// The connection may drop immediately after this returns true.
        /// </summary>
        public bool IsConnected =>
            _tcpConnection?.Connected == true
            && !_disconnectReceived
            && _isDisposed == 0
            && (_sshClientState == State.Connected || _sshClientState == State.Authenticated);

        /// <summary>
        /// ConnectionInfo contains connection information of the SshClient.
        /// </summary>
        public SshConnectionInfo ConnectionInfo { get; }

        /// <summary>
        /// Banner holds the banner message sent by the SSH server after login. If null, no banner was sent.
        /// </summary>
        public string Banner { get; private set; }

        /// <summary>
        /// When set, calls this callback function to determine if the host key is valid and if the connection should continue.
        /// </summary>
        public Func<ReadOnlyMemory<byte>, bool> HostKeyCallback { get; init; }

        /// <summary>
        /// Configures which algorithms are offered during key exchange. Defaults to all supported algorithms.
        /// </summary>
        public SshAlgorithms Algorithms { get; init; } = new();

        /// <summary>
        /// An SshClient that can connect designated hostname and port.
        /// </summary>
        /// <param name="hostname">The remote SSH Server.</param>
        /// <param name="port">The remote SSH port.</param>
        public SshClient(string hostname, ushort port = 22)
        {
            ConnectionInfo = new SshConnectionInfo { Hostname = hostname, Port = port };
        }

        /// <summary>
        /// ConnectAsync connects to the SSH server.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            // Validate current state of SshClient
            if (_sshClientState != State.Initial)
            {
                ThrowOnInvalidState();
            }

            // Set new state of SshClient
            _sshClientState = State.Connecting;

            try
            {
                // Set SshClient defaults
                ConnectionInfo.KeyExchanger = new SshKeyExchanger(ConnectionInfo, HostKeyCallback, Algorithms);
                ConnectionInfo.KeyExchanger.OnSend = WriteMessageAsync;

                // Perform version exchange and key exchange
                ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken).ConfigureAwait(false);

                // Register key exchanger to receive kex-related messages
                _disposables.Add((IAsyncDisposable)RegisterMessageHandler(ConnectionInfo.KeyExchanger));

                var keyExchangeTask = ConnectionInfo.KeyExchanger.HandleKeyExchangeAsync(cancellationToken);
                await ConnectionInfo.KeyExchanger.Ready.ConfigureAwait(false);

                // Start the read loop. When the loop exits for any reason,
                async Task readLoop()
                {
                    Exception loopError = null;
                    try
                    {
                        while (true)
                        {
                            await ReadMessageAsync(_closeCts.Token);
                        }
                    }
                    catch (Exception ex)
                    {
                        loopError = ex;
                    }
                    finally
                    {
                        _closeCts.Cancel();
                        NotifyHandlersOfError(loopError);
                    }
                }
                _readLoop = readLoop();

                await ConnectionInfo.KeyExchanger.InitialKeyExchangeComplete.ConfigureAwait(false);
                _sshClientState = State.Connected;
            }
            catch
            {
                _sshClientState = State.Error;
                _tcpStream?.Dispose();
                _tcpConnection?.Dispose();
                throw;
            }
        }

        /// <summary>
        /// AuthenticateAsync authenticates to the SSH server with the specific username and password.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="password">The password to login with. Note: stored as an immutable string in memory;
        /// SecureString is deprecated in .NET Core and offers no real protection.</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task AuthenticateAsync(string username, string password, CancellationToken cancellationToken)
        {
            // Validate current state of SshClient
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            var auth = EnsureAuthentication();
            using var _ = RegisterMessageHandler(auth);
            await auth.LoginAsync(username, new PasswordAuth(password), cancellationToken).ConfigureAwait(false);
            _sshClientState = State.Authenticated;
        }

        /// <summary>
        /// AuthenticateAsync authenticates to the SSH server with the specified username and authentication method.
        /// </summary>
        public async Task AuthenticateAsync(string username, IAuthMethod authMethod, CancellationToken cancellationToken)
        {
            if (!IsConnected)
                ThrowOnInvalidState();
            var auth = EnsureAuthentication();
            using var _ = RegisterMessageHandler(auth);
            await auth.LoginAsync(username, authMethod, cancellationToken).ConfigureAwait(false);
            _sshClientState = State.Authenticated;
        }

        /// <summary>
        /// AuthenticateAsync authenticates to the SSH server with the specific username and interactive login callback.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="interactiveResponse">interactiveResponse is a callback to a method for interactive login</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task AuthenticateAsync(
            string username,
            Func<string, CancellationToken, Task<string>> interactiveResponse,
            CancellationToken cancellationToken
        )
        {
            // Validate current state of SshClient
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            var auth = EnsureAuthentication();
            using var _ = RegisterMessageHandler(auth);
            await auth.LoginAsync(username, new KeyboardInteractiveAuth(interactiveResponse), cancellationToken).ConfigureAwait(false);
            _sshClientState = State.Authenticated;
        }

        /// <summary>
        /// AuthenticateAsync authenticates to the SSH server by trying all keys from the SSH agent.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="agent">The SSH agent client</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        public async Task AuthenticateAsync(string username, SshAgentClient agent, CancellationToken cancellationToken)
        {
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            var auth = EnsureAuthentication();
            using var _ = RegisterMessageHandler(auth);
            var keys = await agent.ListKeysAsync(cancellationToken).ConfigureAwait(false);
            if (keys.Count == 0)
                throw new Exceptions.SshAuthenticationException("The SSH agent has no keys.");
            var methods = new List<IAuthMethod>();
            foreach (var key in keys)
                methods.Add(new AgentAuth(agent, key));
            await auth.LoginAsync(username, methods, cancellationToken).ConfigureAwait(false);
            _sshClientState = State.Authenticated;
        }

        /// <summary>
        /// AuthenticateAsync authenticates to the SSH server using a specific SSH agent key.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="agent">The SSH agent client</param>
        /// <param name="key">The agent key to authenticate with</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        public async Task AuthenticateAsync(string username, SshAgentClient agent, SshAgentKey key, CancellationToken cancellationToken)
        {
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            var auth = EnsureAuthentication();
            using var _ = RegisterMessageHandler(auth);
            await auth.LoginAsync(username, new AgentAuth(agent, key), cancellationToken).ConfigureAwait(false);
            _sshClientState = State.Authenticated;
        }

        /// <summary>
        /// Creates a raw SSH channel. Use this to build custom channel types (subsystems, tunnels, etc.).
        /// The channel is opened as a session and ready for requests.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the channel request</param>
        /// <returns>An opened SSH channel</returns>
        public async Task<SshChannel> CreateChannelAsync(CancellationToken cancellationToken)
        {
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            var channel = new SshChannel((uint)Interlocked.Increment(ref _channelCounter));
            channel.Registration = RegisterMessageHandler(channel);

            _disposables.Add(channel);

            await channel
                .OpenAsync(new Messages.Channel.Open.ChannelOpenSession(channel.ClientId, 50000), cancellationToken)
                .ConfigureAwait(false);
            return channel;
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

            var channel = new SshChannel((uint)Interlocked.Increment(ref _channelCounter));
            channel.Registration = RegisterMessageHandler(channel);
            var terminal = new SshTerminal(channel);

            _disposables.Add(terminal);

            await terminal.OpenAsync(cancellationToken).ConfigureAwait(false);
            return terminal;
        }

        /// <summary>
        /// Requests the result of a command from the SSH server.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token used to cancel the terminal request</param>
        /// <returns>A task representing the state of the terminal request</returns>
        public async Task<SshCommand> CreateCommandAsync(CancellationToken cancellationToken, bool combineStderr = false)
        {
            // Validate current state of SshClient
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            var channel = new SshChannel((uint)Interlocked.Increment(ref _channelCounter)) { CombineStderr = combineStderr };
            channel.Registration = RegisterMessageHandler(channel);
            var command = new SshCommand(channel) { CombineStderr = combineStderr };

            _disposables.Add(command);

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
                    var readTask = _tcpStream
                        .ReadAsync(buffer.AsMemory(bufferPosition, buffer.Length - bufferPosition), cancellationToken)
                        .AsTask();
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
                await _tcpStream.WriteAsync(clientVersionBytes.AsMemory(), cancellationToken).ConfigureAwait(false);
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
                // Auth and other messages are delivered to registered handlers below.
                // Channel messages are delivered to registered handlers below.
            }

            // Deliver to registered message handlers
            var handlers = _messageHandlers;
            foreach (var handler in handlers)
                await handler.ProcessMessageAsync(messageEvent).ConfigureAwait(false);

            // After delivering SSH_MSG_NEWKEYS, wait for the key exchanger
            // to provide the new read-side crypto before reading the next packet.
            if (messageEvent.Type == MessageType.SSH_MSG_NEWKEYS)
            {
                var applyReadCrypto = await ConnectionInfo.KeyExchanger.GetNewReadKeysAsync(cancellationToken).ConfigureAwait(false);
                applyReadCrypto();
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
                var sshPacket = new SshPacket(message.GetByteWriter(), Math.Max(ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize, 8));
                ByteWriter.WriteUint(sshPacket.Buffer.AsSpan(SshPacket.SequenceIndex), ConnectionInfo.OutboundPacketSequence);
                byte[] macOutput = ConnectionInfo.WriteMacAlgorithm.ComputeHash(ConnectionInfo.OutboundPacketSequence, sshPacket);

                ConnectionInfo.WriteCryptoAlgorithm.Encrypt(sshPacket.Buffer, sshPacket.Offset, sshPacket.Length);
                await _tcpStream
                    .WriteAsync(sshPacket.Buffer.AsMemory(sshPacket.Offset, sshPacket.Length), cancellationToken)
                    .ConfigureAwait(false);

                if (ConnectionInfo.WriteMacAlgorithm.OutputSize != 0)
                {
                    await _tcpStream
                        .WriteAsync(macOutput.AsMemory(0, ConnectionInfo.WriteMacAlgorithm.OutputSize), cancellationToken)
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
            if (Interlocked.Exchange(ref _isDisposed, 1) == 0)
            {
                _sshClientState = State.Closed;
                ConnectionInfo.Dispose();
                _tcpStream?.Dispose();
                _tcpConnection?.Dispose();
                _writeSemaphore.Dispose();
            }
        }

        /// <summary>
        /// Throws an SshException if the SshClient is in an invalid state to continue.
        /// </summary>
        private SshAuthentication _authentication;

        private SshAuthentication EnsureAuthentication()
        {
            if (_authentication == null)
            {
                _authentication = new SshAuthentication(() => ConnectionInfo.SessionIdentifier);
                _authentication.OnBanner = banner => Banner = banner;
            }
            return _authentication;
        }

        private void ThrowOnInvalidState()
        {
            switch (_sshClientState)
            {
                case State.Connecting:
                    throw new SshException($"The {nameof(SshClient)} is already attempting a connection.");
                case State.Connected:
                    throw new SshException($"The {nameof(SshClient)} is connected but not authenticated.");
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
            // Best-effort: send disconnect before tearing down
            if (IsConnected)
            {
                try
                {
                    await WriteMessageAsync(
                            new Messages.Disconnect(
                                Messages.Disconnect.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
                                "Client disconnecting"
                            ),
                            CancellationToken.None
                        )
                        .ConfigureAwait(false);
                }
                catch { }
            }

            _closeCts.Cancel();

            foreach (var disposable in _disposables)
            {
                try
                {
                    await disposable.DisposeAsync().ConfigureAwait(false);
                }
                catch { }
            }

            Close();
            if (_readLoop != null)
            {
                try
                {
                    await _readLoop;
                }
                catch (Exception) { }
            }
            _closeCts.Dispose();
        }

        /// <summary>
        /// The state the SshClient is in
        /// </summary>
        internal enum State
        {
            Initial,
            Connecting,
            Connected,
            Authenticated,
            Closed,
            Error,
        }
    }
}
