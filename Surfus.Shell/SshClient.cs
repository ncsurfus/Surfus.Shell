using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
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
        /// Cancellation Token Source that is cancelled when the client is closing.
        /// </summary>
        private readonly CancellationTokenSource _closeCts = new();

        /// <summary>
        /// _stream holds the underlying stream for the SSH connection.
        /// </summary>
        private Stream? _stream;

        /// <summary>
        /// Optional factory that provides the transport stream and an optional close callback.
        /// </summary>
        private readonly Func<CancellationToken, Task<(Stream Stream, Func<ValueTask>? OnCloseAsync)>> _streamFactory;

        /// <summary>
        /// Callback invoked once when the client is closed, to clean up the transport.
        /// </summary>
        private Func<ValueTask>? _onCloseAsync;
        private int _onCloseCalled;

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

        private void NotifyHandlersOfError(Exception? error)
        {
            var handlers = _messageHandlers;
            foreach (var handler in handlers)
            {
                handler.OnError(error ?? new Exceptions.SshException("Connection closed."));
            }
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
        private Task? _readLoop;

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
            !_disconnectReceived
            && _isDisposed == 0
            && (_sshClientState == State.Connected || _sshClientState == State.Authenticated);

        /// <summary>
        /// ConnectionInfo contains connection information of the SshClient.
        /// </summary>
        public SshConnectionInfo ConnectionInfo { get; }

        /// <summary>
        /// Banner holds the banner message sent by the SSH server after login. If null, no banner was sent.
        /// </summary>
        public string? Banner { get; private set; }

        /// <summary>
        /// When set, calls this callback function to determine if the host key is valid and if the connection should continue.
        /// </summary>
        public Func<ReadOnlyMemory<byte>, CancellationToken, Task<bool>>? HostKeyCallback { get; init; }

        /// <summary>
        /// Configures which algorithms are offered during key exchange. Defaults to all supported algorithms.
        /// </summary>
        public SshAlgorithms Algorithms { get; init; } = new();

        /// <summary>
        /// An SshClient that connects to the designated hostname and port.
        /// </summary>
        public SshClient(string hostname, ushort port = 22)
        {
            _streamFactory = async ct =>
            {
                var tcp = new TcpClient();
                try
                {
                    var timeout = new TaskCompletionSource<bool>();
                    using (ct.Register(() => timeout.SetResult(true)))
                    {
                        var connectTask = tcp.ConnectAsync(hostname, port);
                        var result = await Task.WhenAny(timeout.Task, connectTask).ConfigureAwait(false);
                        if (result == timeout.Task)
                        {
                            throw new OperationCanceledException("The operation was cancelled during the TCP connect.", ct);
                        }
                        await connectTask.ConfigureAwait(false);
                    }
                }
                catch
                {
                    tcp.Dispose();
                    throw;
                }
                return (tcp.GetStream(), () => { tcp.Dispose(); return ValueTask.CompletedTask; });
            };
            ConnectionInfo = new SshConnectionInfo();
        }

        /// <summary>
        /// An SshClient that uses a custom stream factory for the transport.
        /// The factory returns a stream and an optional callback invoked when the client is closed.
        /// </summary>
        public SshClient(Func<CancellationToken, Task<(Stream Stream, Func<ValueTask>? OnCloseAsync)>> streamFactory)
        {
            ArgumentNullException.ThrowIfNull(streamFactory);
            _streamFactory = streamFactory;
            ConnectionInfo = new SshConnectionInfo();
        }

        /// <summary>
        /// An SshClient that uses an existing stream for the transport.
        /// The caller must not dispose the stream while the client is in use; the client takes ownership.
        /// </summary>
        public SshClient(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);
            _streamFactory = _ => Task.FromResult<(Stream, Func<ValueTask>?)>((stream, null));
            ConnectionInfo = new SshConnectionInfo();
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
                ConnectionInfo.KeyExchanger = new SshKeyExchanger(ConnectionInfo, HostKeyCallback, Algorithms)
                {
                    OnSend = WriteMessageAsync
                };

                // Perform version exchange and key exchange
                ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken).ConfigureAwait(false);

                // Register key exchanger to receive kex-related messages
                _disposables.Add((IAsyncDisposable)RegisterMessageHandler(ConnectionInfo.KeyExchanger));

                var keyExchangeTask = ConnectionInfo.KeyExchanger.HandleKeyExchangeAsync(cancellationToken);
                await ConnectionInfo.KeyExchanger.Ready.ConfigureAwait(false);

                // Start the read loop. When the loop exits for any reason,
                async Task readLoop()
                {
                    Exception? loopError = null;
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
                if (_onCloseAsync != null && Interlocked.Exchange(ref _onCloseCalled, 1) == 0)
                {
                    await _onCloseAsync().ConfigureAwait(false);
                }
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
            {
                ThrowOnInvalidState();
            }
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
            {
                throw new Exceptions.SshAuthenticationException("The SSH agent has no keys.");
            }
            var methods = new List<IAuthMethod>();
            foreach (var key in keys)
            {
                methods.Add(new AgentAuth(agent, key));
            }
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
        /// <param name="options">Optional terminal configuration (type, size). Defaults to xterm 80x24.</param>
        /// <returns>A task representing the state of the terminal request</returns>
        public async Task<SshTerminal> CreateTerminalAsync(CancellationToken cancellationToken, TerminalOptions? options = null)
        {
            // Validate current state of SshClient
            if (!IsConnected)
            {
                ThrowOnInvalidState();
            }

            var channel = new SshChannel((uint)Interlocked.Increment(ref _channelCounter));
            channel.Registration = RegisterMessageHandler(channel);
            var terminal = new SshTerminal(channel, options);

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
            var (stream, onCloseAsync) = await _streamFactory(cancellationToken).ConfigureAwait(false);
            _stream = stream;
            _onCloseAsync = onCloseAsync;

            // Buffer to receive their version.
            var buffer = new byte[255];
            var bufferPosition = 0;
            var ignoreText = false;
            var readingVersion = false;

            // Some stream implementations (e.g. NetworkStream) may not respond to the
            // cancellation token passed to ReadAsync. Use Task.WhenAny as a workaround.
            var cancelled = new TaskCompletionSource<bool>();
            using var ctReg = cancellationToken.Register(() => cancelled.SetResult(true));

            while (bufferPosition == 0 || buffer[bufferPosition - 1] != '\n')
            {
                if (bufferPosition == buffer.Length)
                {
                    throw new SshException($"Failed to exchange SSH version. Version size is greater than {buffer.Length}.");
                }

                var readTask = _stream
                    .ReadAsync(buffer.AsMemory(bufferPosition, buffer.Length - bufferPosition), cancellationToken)
                    .AsTask();
                var result = await Task.WhenAny(cancelled.Task, readTask).ConfigureAwait(false);

                if (result == cancelled.Task)
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
                    bufferPosition += readAmount;
                }
                else if (!ignoreText && buffer[0] == 'S' && buffer[1] == 'S' && buffer[2] == 'H' && buffer[3] == '-')
                {
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
                            for (var j = 0; j != bufferPosition + readAmount - i - 1; j++)
                            {
                                buffer[j] = buffer[i + j + 1];
                            }
                            bufferPosition = bufferPosition - i + readAmount - 1;
                            readAmount = 0;

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
            await _stream.WriteAsync(clientVersionBytes.AsMemory(), cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return version;
        }

        /// <summary>
        /// Reads a message from the server
        /// </summary>
        /// <param name="cancellationToken">The cancellation token is used to cancel the ReadMessage request</param>
        /// <returns></returns>
        private async Task ReadMessageAsync(CancellationToken cancellationToken)
        {
            var sshPacketTask = ConnectionInfo.ReadCryptoAlgorithm.ReadPacketAsync(
                _stream!,
                ConnectionInfo.InboundPacketSequence,
                ConnectionInfo.ReadMacAlgorithm.OutputSize,
                ConnectionInfo.ReadMacAlgorithm.IsEtm,
                cancellationToken
            );

            var sshPacket = await sshPacketTask.ConfigureAwait(false);

            if (ConnectionInfo.ReadMacAlgorithm.OutputSize != 0)
            {
                if (!ConnectionInfo.ReadMacAlgorithm.VerifyMac(ConnectionInfo.InboundPacketSequence, sshPacket))
                {
                    throw new SshException("The server sent a malformed message.");
                }

                if (ConnectionInfo.ReadMacAlgorithm.IsEtm)
                {
                    // ETM: MAC verified over ciphertext, now decrypt the body (skip the 4-byte packet length).
                    ConnectionInfo.ReadCryptoAlgorithm.Decrypt(sshPacket.Buffer, sshPacket.Offset + 4, sshPacket.Length - 4);
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

            // Deliver to registered message handlers
            var handlers = _messageHandlers;
            foreach (var handler in handlers)
            {
                await handler.ProcessMessageAsync(messageEvent).ConfigureAwait(false);
            }

            // After delivering SSH_MSG_NEWKEYS, wait for the key exchanger
            // to provide the new read-side crypto before reading the next packet.
            if (messageEvent.Type == MessageType.SSH_MSG_NEWKEYS)
            {
                var applyReadCrypto = await ConnectionInfo.KeyExchanger!.GetNewReadKeysAsync(cancellationToken).ConfigureAwait(false);
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
                var sshPacket = new SshPacket(message.GetByteWriter(), Math.Max(ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize, 8), ConnectionInfo.WriteMacAlgorithm.IsEtm);
                ByteWriter.WriteUint(sshPacket.Buffer.AsSpan(SshPacket.SequenceIndex), ConnectionInfo.OutboundPacketSequence);

                byte[] macOutput;
                if (ConnectionInfo.WriteMacAlgorithm.IsEtm)
                {
                    // ETM: encrypt body (not packet length), then MAC over seq + length + ciphertext
                    ConnectionInfo.WriteCryptoAlgorithm.Encrypt(sshPacket.Buffer, sshPacket.Offset + 4, sshPacket.Length - 4);
                    macOutput = ConnectionInfo.WriteMacAlgorithm.ComputeHash(ConnectionInfo.OutboundPacketSequence, sshPacket);
                }
                else
                {
                    macOutput = ConnectionInfo.WriteMacAlgorithm.ComputeHash(ConnectionInfo.OutboundPacketSequence, sshPacket);
                    ConnectionInfo.WriteCryptoAlgorithm.Encrypt(sshPacket.Buffer, sshPacket.Offset, sshPacket.Length);
                }

                var writeLength = ConnectionInfo.WriteCryptoAlgorithm.IsAead
                    ? sshPacket.Length + 16 // AEAD tag appended by Encrypt
                    : sshPacket.Length;

                await _stream!
                    .WriteAsync(sshPacket.Buffer.AsMemory(sshPacket.Offset, writeLength), cancellationToken)
                    .ConfigureAwait(false);

                if (ConnectionInfo.WriteMacAlgorithm.OutputSize != 0)
                {
                    await _stream
                        .WriteAsync(macOutput.AsMemory(0, ConnectionInfo.WriteMacAlgorithm.OutputSize), cancellationToken)
                        .ConfigureAwait(false);
                }

                await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
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
                _stream?.Dispose();
                _writeSemaphore.Dispose();
            }
        }

        /// <summary>
        /// Throws an SshException if the SshClient is in an invalid state to continue.
        /// </summary>
        private SshAuthentication? _authentication;

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
            if (_onCloseAsync != null && Interlocked.Exchange(ref _onCloseCalled, 1) == 0)
            {
                await _onCloseAsync().ConfigureAwait(false);
            }
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
