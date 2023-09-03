using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using Surfus.Shell.Messages.UserAuth;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

        /// <summary>
        /// A list of callbacks that are invoked anytime a new message is received. If they return
        /// True, then the callback is removed.
        /// </summary>
        private ImmutableList<Func<MessageEvent, Task>> _callbacks = ImmutableList.Create<Func<MessageEvent, Task>>();

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
            ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
            ConnectionInfo.Authentication = new SshAuthentication(this);

            // Perform version exchange and key exchange
            ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken).ConfigureAwait(false);

            var keyExchangeTask = ConnectionInfo.KeyExchanger.HandleKeyExchangeAsync(cancellationToken);
            await ConnectionInfo.KeyExchanger.Ready.ConfigureAwait(false);

            // Start the read loop
            async Task readLoop()
            {
                while (true)
                {
                    await ReadMessageAsync(_closeCts.Token);
                }
            }
            ;
            _readLoop = readLoop();

            await ConnectionInfo.KeyExchanger.InitialKeyExchangeComplete.ConfigureAwait(false);
            _sshClientState = State.Authenticating;
        }

        /// <summary>
        /// AuthenticateAsync authenticates to the SSH server with the specific username and password.
        /// </summary>
        /// <param name="username">The username to login as</param>
        /// <param name="password">The password to login with</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the connection request</param>
        /// <returns>A task representing the state of the connection attempt</returns>
        public async Task AuthenticateAsync(string username, string password, CancellationToken cancellationToken)
        {
            // Validate current state of SshClient
            if (_sshClientState != State.Authenticating)
            {
                ThrowOnInvalidState();
            }

            await ConnectionInfo.Authentication.LoginAsync(username, password, cancellationToken).ConfigureAwait(false);
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
            if (_sshClientState != State.Authenticating)
            {
                ThrowOnInvalidState();
            }

            await ConnectionInfo.Authentication.LoginAsync(username, interactiveResponse, cancellationToken).ConfigureAwait(false);
            _sshClientState = State.Authenticated;
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
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal async Task<MessageEvent> ReadUntilAsync(
            Func<Task> onReading,
            Func<MessageEvent, ValueTask<bool>> condition,
            CancellationToken cancellationToken
        )
        {
            // Create a TaskCompletionSource that completes once the message is spotted.
            var tcs = new TaskCompletionSource<MessageEvent>();

            // The TaskCompletionSource should be cleaned up if the SSH Client is disposed.
            using (_closeCts.Token.Register(() => tcs.TrySetCanceled()))
            {
                async Task callbackAsync(MessageEvent messageEvent)
                {
                    try
                    {
                        if (await condition(messageEvent))
                        {
                            tcs.TrySetResult(messageEvent);
                        }
                    }
                    catch (Exception ex)
                    {
                        tcs.TrySetException(ex);
                    }
                }

                // Add our callback into the read loop
                lock (_callbacks)
                {
                    _callbacks = _callbacks.Add(callbackAsync);
                }

                // Run any code, like sending a message
                if (onReading is not null)
                {
                    await onReading();
                }

                // Wait for the task to complete, and then perform cleanup
                try
                {
                    return await tcs.Task;
                }
                finally
                {
                    lock (_callbacks)
                    {
                        _callbacks = _callbacks.Remove(callbackAsync);
                    }
                }
            }
        }

        /// <summary>
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal Task<MessageEvent> ReadUntilAsync(
            Func<Task> onReading,
            Func<MessageEvent, bool> condition,
            CancellationToken cancellationToken
        )
        {
            ValueTask<bool> conditionWrapper(MessageEvent messageEvent)
            {
                return ValueTask.FromResult(condition(messageEvent));
            }
            return ReadUntilAsync(onReading, conditionWrapper, cancellationToken);
        }

        /// <summary>
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal Task<MessageEvent> ReadUntilAsync(Func<MessageEvent, bool> condition, CancellationToken cancellationToken)
        {
            ValueTask<bool> conditionWrapper(MessageEvent messageEvent)
            {
                return ValueTask.FromResult(condition(messageEvent));
            }
            return ReadUntilAsync(null, conditionWrapper, cancellationToken);
        }

        /// <summary>
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal Task<MessageEvent> ReadUntilAsync(Func<Task> onReading, MessageType messageType, CancellationToken cancellationToken)
        {
            ValueTask<bool> conditionWrapper(MessageEvent messageEvent)
            {
                return ValueTask.FromResult(messageEvent.Type == messageType);
            }
            return ReadUntilAsync(onReading, conditionWrapper, cancellationToken);
        }

        /// <summary>
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal Task<MessageEvent> ReadUntilAsync(MessageType messageType, CancellationToken cancellationToken)
        {
            ValueTask<bool> conditionWrapper(MessageEvent messageEvent)
            {
                return ValueTask.FromResult(messageEvent.Type == messageType);
            }
            return ReadUntilAsync(null, conditionWrapper, cancellationToken);
        }

        /// <summary>
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal async Task<T> ReadUntilAsync<T>(Func<Task> onReading, CancellationToken cancellationToken)
            where T : class, IMessage
        {
            static ValueTask<bool> conditionWrapper(MessageEvent messageEvent)
            {
                return ValueTask.FromResult(messageEvent.Message is T);
            }
            var result = await ReadUntilAsync(onReading, conditionWrapper, cancellationToken);
            return result.Message as T;
        }

        /// <summary>
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal async Task<T> ReadUntilAsync<T>(CancellationToken cancellationToken)
            where T : class, IMessage
        {
            static ValueTask<bool> conditionWrapper(MessageEvent messageEvent)
            {
                return ValueTask.FromResult(messageEvent.Message is T);
            }
            var result = await ReadUntilAsync(null, conditionWrapper, cancellationToken);
            return result.Message as T;
        }

        /// <summary>
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal async Task ReadWhileAsync(Func<bool> condition, CancellationToken cancellationToken)
        {
            await ReadUntilAsync(null, (_) => !condition(), cancellationToken);
        }

        /// <summary>
        /// Reads packets one-by-one from the server until the callback method returns false.
        /// </summary>
        /// <returns></returns>
        internal async Task ReadWhileAsync(Func<Task<bool>> condition, CancellationToken cancellationToken)
        {
            await ReadUntilAsync(null, async (_) => !await condition(), cancellationToken);
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
            }

            // Get a local reference of the current callbacks
            var callbacks = _callbacks;
            foreach (var callback in callbacks)
            {
                await callback(messageEvent);
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
                    await ConnectionInfo.Authentication
                        .ProcessMessageAsync(messageEvent.Message as ServiceAccept, cancellationToken)
                        .ConfigureAwait(false);
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
                    await ConnectionInfo.Authentication
                        .ProcessMessageAsync(messageEvent.Message as UaInfoRequest, cancellationToken)
                        .ConfigureAwait(false);
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
                if (!_channels.ContainsKey(channelMessage.RecipientChannel))
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
        /// Processes packets in the background until the connection has been disconnected.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task ProcessPacketsAsync(CancellationToken cancellationToken)
        {
            await ReadWhileAsync(() => IsConnected, cancellationToken);
        }

        /// <summary>
        /// Processes packets in the background until the condition has been met.
        /// </summary>
        /// <param name="condition">The condition that must be true to exit the method.</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task ProcessPacketsWhileAsync(Func<bool> condition, CancellationToken cancellationToken)
        {
            await ReadWhileAsync(condition, cancellationToken);
        }

        /// <summary>
        /// Processes packets in the background until the condition has been met.
        /// </summary>
        /// <param name="condition">The condition that must be true to exit the method.</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task ProcessPacketsWhileAsync(Func<Task<bool>> condition, CancellationToken cancellationToken)
        {
            await ReadWhileAsync(condition, cancellationToken);
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
            await ReadWhileAsync(() => !taskTimer.IsCompleted, cancellationToken);
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
            await ReadWhileAsync(() => !taskTimer.IsCompleted, cancellationToken);
            await taskTimer;
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
