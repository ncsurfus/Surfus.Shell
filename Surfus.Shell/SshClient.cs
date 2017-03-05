using NLog;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages;
//using Surfus.Shell.Messages.Channel;
//using Surfus.Shell.Messages.KeyExchange;
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
    public class SshClient : IDisposable
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        // Fields
        private bool _connectAsyncCalled = false;
        private Task _readLoopTask;
        private SemaphoreSlim _connectSemaphore = new SemaphoreSlim(1,1);
        internal TaskCompletionSource<bool> InitialKeyExchangeCompleted { get; set; }
        internal TaskCompletionSource<bool> LoginCompleted { get; set; }

        // Network Connection
        internal TcpClient TcpConnection { get; } = new TcpClient();
        internal NetworkStream TcpStream => TcpConnection.GetStream();

        // Channels
       // uint _channelCounter = 0;
        //internal List<SshChannel> Channels = new List<SshChannel>();
      //  internal List<SshCommand> Commands = new List<SshCommand>();
    //    internal List<SshTerminal> Terminals = new List<SshTerminal>();

        // Internal CancellationToken
        internal CancellationTokenSource InternalCancellation = new CancellationTokenSource();

        public bool IsConnected => TcpConnection.Connected && !_isDisposed;

        // Connection Info
        public SshConnectionInfo ConnectionInfo = new SshConnectionInfo();

        public string Banner { get; private set; } = null;

        // Dispose
        private bool _isDisposed = false;
        internal bool IsFinished => _isDisposed;

        public SshClient(string hostname) : this(hostname, 22)
        {
        }

        public SshClient(string hostname, ushort port)
        {
            ConnectionInfo.Hostname = hostname;
            ConnectionInfo.Port = port;
        }
        /*
        public async Task<SshCommand> CreateCommandAsync(CancellationToken cancellationToken)
        {
            // Channels will be touched by background thread. Must coordinate.
            await SshClientSemaphore.WaitAsync(cancellationToken);

            var channel = new SshChannel(this, _channelCounter);
            var command = new SshCommand(this, channel);
            Commands.Add(command);

            Channels.Add(channel);
            _channelCounter++;

            SshClientSemaphore.Release();

            return command;
        }

        public async Task<SshTerminal> CreateTerminalAsync(CancellationToken cancellationToken)
        {
            // Channels will be touched by background thread. Must coordinate.
            await SshClientSemaphore.WaitAsync(cancellationToken);

            var channel = new SshChannel(this, _channelCounter);
            var terminal = new SshTerminal(this, channel);
            Terminals.Add(terminal);

            Channels.Add(channel);
            _channelCounter++;

            SshClientSemaphore.Release();

            return terminal;
        }

        internal async Task SendChannelMessageAsync(MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            // Runs on background thread
            logger.Debug($"Checking Channel Message Type");
            if (messageEvent.Message is IChannelRecipient channelMessage)
            {
                // Channels will be touched by foreground thread. Must coordinate.
                await SshClientSemaphore.WaitAsync(cancellationToken);
                var channel = Channels.Single(x => x.ClientId == channelMessage.RecipientChannel);
                SshClientSemaphore.Release();

                switch (messageEvent.Message)
                {
                    case ChannelSuccess success:
                        channel.SendMessage(success);
                        break;
                    case ChannelFailure failure:
                        channel.SendMessage(failure);
                        break;
                    case ChannelOpenConfirmation openConfirmation:
                        channel.SendMessage(openConfirmation);
                        break;
                    case ChannelOpenFailure openFailure:
                        channel.SendMessage(openFailure);
                        break;
                    case ChannelWindowAdjust windowAdjust:
                        channel.SendMessage(windowAdjust);
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
        */

        public async Task ConnectAsync(string username, string password, CancellationToken cancellationToken)
        {
            await _connectSemaphore.WaitAsync();
            
            if (_connectAsyncCalled)
            {
                throw new SshException($"ConnectAsync was already attempted. A new SshClient should be created.");
            }

            _connectAsyncCalled = true;
            _connectSemaphore.Release();

            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, InternalCancellation.Token))
            {
                linkedCancellation.Token.Register(() => InitialKeyExchangeCompleted?.TrySetCanceled());

                ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
                ConnectionInfo.Authentication = new SshAuthentication(this);

                InitialKeyExchangeCompleted = new TaskCompletionSource<bool>();
                ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken);
                _logger.Info("Server Version: " + ConnectionInfo.ServerVersion);
                _readLoopTask = ReadLoop();
                await InitialKeyExchangeCompleted.Task;

                LoginCompleted = new TaskCompletionSource<bool>();
                await ConnectionInfo.Authentication.LoginAsync(username, password, linkedCancellation.Token);
                await LoginCompleted.Task;
            }
        }

        public async Task ConnectAsync(string username, Func<string, CancellationToken, Task<string>> interactiveResponse, CancellationToken cancellationToken)
        {
            await _connectSemaphore.WaitAsync();

            if (_connectAsyncCalled)
            {
                throw new SshException($"ConnectAsync was already attempted. A new SshClient should be created.");
            }

            _connectAsyncCalled = true;
            _connectSemaphore.Release();

            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, InternalCancellation.Token))
            {
                linkedCancellation.Token.Register(() => InitialKeyExchangeCompleted?.TrySetCanceled());

                ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
                ConnectionInfo.Authentication = new SshAuthentication(this);

                InitialKeyExchangeCompleted = new TaskCompletionSource<bool>();
                ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken);
                _logger.Info("Server Version: " + ConnectionInfo.ServerVersion);
                _readLoopTask = ReadLoop();
                await InitialKeyExchangeCompleted.Task;

                LoginCompleted = new TaskCompletionSource<bool>();
                await ConnectionInfo.Authentication.LoginAsync(username, interactiveResponse, linkedCancellation.Token);
                await LoginCompleted.Task;
            }
        }

        public async Task ReadLoop()
        {
            try
            {
                _logger.Info("Starting Message Read Loop...");
                while (IsConnected && !InternalCancellation.IsCancellationRequested)
                {
                    await ReadMessageAsync(InternalCancellation.Token);
                }
                _logger.Info("Ending Message Read Loop...");
            }
            catch (Exception ex)
            {
                InitialKeyExchangeCompleted?.TrySetException(ex);
                LoginCompleted?.TrySetException(ex);
                _logger.Fatal("Caught Exception in Read Loop: " + ex.ToString());
            }
        }
        /*
        public async Task ConnectAsync(string username, Func<string, CancellationToken, Task<string>> InteractiveDelegate, CancellationToken cancellationToken)
        {
            ConnectionInfo.KeyExchanger = new SshKeyExchanger(this);
            ConnectionInfo.ServerVersion = await ExchangeVersionAsync(cancellationToken);
            var connectionInfo = ConnectionInfo.KeyExchanger.ExchangeKeysAsync(cancellationToken);
            await ConnectionInfo.Authentication.LoginInteractiveAsync(username, InteractiveDelegate, InternalCancellation.Token);
        }
       
        public async Task<string> GetBannerAsync(CancellationToken cancellationToken)
        {
            // If this cancels, we must cancel the TaskCompeletionSource and Background Thread...
            cancellationToken.Register(() => SetException(new TaskCanceledException(LoginBannerTaskSource.Task)));

            return await LoginBannerTaskSource.Task;
        }
        
        internal void SetException(Exception ex)
        {
            logger.Trace($"{ConnectionInfo.Hostname} - Entering {nameof(SetException)}");
            if (!IsFinished)
            {
                logger.Fatal($"{ConnectionInfo.Hostname}: {ex}");
            }
            else
            {
                logger.Debug($"{ConnectionInfo.Hostname} (After Fatal/Success): {ex.Message}");
            }
            SetTaskExceptions(ex);
            Close(nameof(SetException));
        }

        private void SetTaskExceptions(Exception ex)
        {
            // Throw exception on tasks on foreground thread
            ConnectTaskSource?.TrySetException(ex);
            LoginTaskSource?.TrySetException(ex);

            // Throw exception on tasks in channel thread

            // Cancel tasks on background thread
            ConnectionInfo.KeyExchanger?.KexInitMessage?.TrySetCanceled();
            ConnectionInfo.KeyExchanger?.NewKeysMessage?.TrySetCanceled();

            // Set Channels
            foreach (var channel in Channels)
            {
                channel.ChannelOpenConfirmationMessage?.TrySetException(ex);
                channel.ChannelSuccessMessage?.TrySetException(ex);
            }

            // Set Commands
            foreach (var command in Commands)
            {
                command.ChannelOpenTaskSource?.TrySetException(ex);
                command.ChannelCloseTaskSource?.TrySetException(ex);
                command.ExecuteEofTaskSource?.TrySetException(ex);
                command.ExecuteCloseTaskSource?.TrySetException(ex);
                command.ExecuteTaskSource?.TrySetException(ex);
            }

            // Set Terminals
            foreach (var terminal in Terminals)
            {
                terminal.ChannelCloseTaskSource?.TrySetException(ex);
                terminal.ChannelOpenTaskSource?.TrySetException(ex);
                terminal.TerminalReadTaskSource?.TrySetException(ex);
                terminal.TerminalWriteTaskSource?.TrySetException(ex);
                terminal.ShellTaskSource?.TrySetException(ex);
                terminal.PseudoTerminalTaskSource?.TrySetException(ex);
            }
        }
         */
        internal async Task SetFatalError(Exception ex)
        {

        }

        public void Close()
        {
            if(!InternalCancellation.IsCancellationRequested)
            {
                InternalCancellation.Cancel(true);
            }
            if(TcpConnection?.Connected == true)
            {
                TcpConnection.Close();
            }
            _isDisposed = true;
        }

        private async Task<string> ExchangeVersionAsync(CancellationToken cancellationToken)
        {
            await TcpConnection.ConnectAsync(ConnectionInfo.Hostname, ConnectionInfo.Port);
            var serverVersionFilter = new Regex(@"^SSH-(?<ProtoVersion>\d\.\d+)-(?<SoftwareVersion>\S+)(?<Comments>\s[^\r\n]+)?", RegexOptions.Compiled);

            // Buffer to receive their version.
            var buffer = new byte[ushort.MaxValue];
            var bufferPosition = 0;

            while (TcpStream.CanRead)
            {
                if (bufferPosition == ushort.MaxValue)
                {
                    throw new ArgumentOutOfRangeException();
                }

                var readAmount = await TcpStream.ReadAsync(buffer, bufferPosition, 1, cancellationToken);
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
                            await TcpStream.WriteAsync(clientVersionBytes, 0, clientVersionBytes.Length, cancellationToken);
                            await TcpStream.FlushAsync(cancellationToken);

                            return serverVersion;
                        }
                    }

                    buffer = new byte[ushort.MaxValue];
                    bufferPosition = 0;
                }
                bufferPosition += readAmount;
            }


            throw new Exception("Invalid version from server");
        }

        private async Task ReadMessageAsync(CancellationToken cancellationToken)
        {
            var sshPacket = await ConnectionInfo.ReadCryptoAlgorithm.ReadPacketAsync(TcpStream, cancellationToken);
            if (ConnectionInfo.ReadMacAlgorithm.OutputSize != 0)
            {
                var messageAuthenticationHash = await TcpStream.ReadBytesAsync((uint)ConnectionInfo.ReadMacAlgorithm.OutputSize, cancellationToken);
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
                    await ConnectionInfo.KeyExchanger.ApplyKeyExchangeMessageAsync(messageEvent, cancellationToken);
                    break;
                case MessageType.SSH_MSG_NEWKEYS:
                    await ConnectionInfo.KeyExchanger.ApplyKeyExchangeMessageAsync(messageEvent, cancellationToken);
                    InitialKeyExchangeCompleted?.TrySetResult(true);
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_30:
                case MessageType.SSH_MSG_KEX_Exchange_31:
                case MessageType.SSH_MSG_KEX_Exchange_32:
                case MessageType.SSH_MSG_KEX_Exchange_33:
                case MessageType.SSH_MSG_KEX_Exchange_34:
                    await ConnectionInfo.KeyExchanger.ApplyKeyExchangeMessageAsync(messageEvent, cancellationToken);
                    break;
                case MessageType.SSH_MSG_SERVICE_ACCEPT:
                    await ConnectionInfo.Authentication.SendMessage(messageEvent.Message as ServiceAccept, cancellationToken);
                    break;
                case MessageType.SSH_MSG_REQUEST_FAILURE:
                    await ConnectionInfo.Authentication.SendRequestFailureMessage(cancellationToken);
                    break;
                case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                    await ConnectionInfo.Authentication.SendMessage(messageEvent.Message as UaSuccess, cancellationToken);
                    LoginCompleted?.TrySetResult(true);
                    break;
                case MessageType.SSH_MSG_USERAUTH_FAILURE:
                    await ConnectionInfo.Authentication.SendMessage(messageEvent.Message as UaFailure, cancellationToken);
                    break;
                case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                    await ConnectionInfo.Authentication.SendMessage(messageEvent.Message as UaInfoRequest, cancellationToken);
                    break;
                case MessageType.SSH_MSG_USERAUTH_BANNER:
                    Banner = (messageEvent.Message as UaBanner)?.Message;
                    break;
               /* case MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                case MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE:
                case MessageType.SSH_MSG_CHANNEL_SUCCESS:
                case MessageType.SSH_MSG_CHANNEL_FAILURE:
                case MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                case MessageType.SSH_MSG_CHANNEL_DATA:
                case MessageType.SSH_MSG_CHANNEL_CLOSE:
                case MessageType.SSH_MSG_CHANNEL_EOF:
                    logger.Debug($"Sending Channel Message to client");
                    await SendChannelMessageAsync(messageEvent, cancellationToken);
                    break;*/
                default:
                    _logger.Info($"{ConnectionInfo.Hostname} - {nameof(ReadMessageAsync)}: Unexpected Message {messageEvent.Type}");
                    break;
            }
        }

        internal async Task WriteMessageAsync(IMessage message, CancellationToken cancellationToken)
        {
            var compressedPayload = ConnectionInfo.WriteCompressionAlgorithm.Compress(message.GetBytes());
            var sshPacket = new SshPacket(compressedPayload,
                    ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize > 8
                    ? ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize : 8);

            await TcpStream.WriteAsync(ConnectionInfo.WriteCryptoAlgorithm.Encrypt(sshPacket.Raw), cancellationToken);

            if (ConnectionInfo.WriteMacAlgorithm.OutputSize != 0)
            {
                await TcpStream.WriteAsync(ConnectionInfo.WriteMacAlgorithm.ComputeHash(ConnectionInfo.OutboundPacketSequence,
                            sshPacket), cancellationToken);
            }

            await TcpStream.FlushAsync(cancellationToken);
            ConnectionInfo.OutboundPacketSequence = ConnectionInfo.OutboundPacketSequence != uint.MaxValue
                                                         ? ConnectionInfo.OutboundPacketSequence + 1
                                                         : 0;

            _logger.Debug($"{ConnectionInfo.Hostname} - {nameof(WriteMessageAsync)}: Sent {message.Type}");
        }

        public void Dispose()
        {
            Close();
        }
    }
}
