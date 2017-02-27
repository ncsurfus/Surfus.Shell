using NLog;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.KeyExchange;
using Surfus.Shell.Messages.UserAuth;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    internal static class SshClientStaticThread
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();
        static SemaphoreSlim _internalSync = new SemaphoreSlim(1);
        static List<ClientTask> _clients = new List<ClientTask>();
        static List<Func<Task>> _tasks = new List<Func<Task>>();
        static TaskCompletionSource<bool> _updateThread = new TaskCompletionSource<bool>();
        static Thread _internalThread;

        internal static async Task AddClientTaskAsync(ClientTask clientTask)
        {
            await _internalSync.WaitAsync();
            _clients.Add(clientTask);

            // Start Task thread if it is null or not alive
            if (_internalThread?.IsAlive != true)
            {
                _internalThread = new Thread(() => { RunTasksAsync().Wait(); });
                _internalThread.Start();
            }

            _updateThread.TrySetResult(true);
            _internalSync.Release();
        }

        internal static async Task ConnectAsync(SshClient client, CancellationToken cancellationToken)
        {
            await AddClientTaskAsync(new ClientTask { Client = client, TaskFunction = async () =>
            {
                try
                {
                    client.ConnectionInfo.ServerVersion = await ExchangeVersionAsync(client, cancellationToken);
                    logger.Info($"{client.ConnectionInfo.Hostname} - {nameof(ConnectAsync)}: Version is {client.ConnectionInfo.ServerVersion}");

                    // Start KeyExchangeListener before getting first packet
                    client.ConnectionInfo.KeyExchanger = new SshKeyExchanger(client);
                    await AddClientTaskAsync(new ClientTask() { Client = client, TaskFunction = () => client.ConnectionInfo.KeyExchanger.ExchangeKeysAsync(cancellationToken) });

                    await ReadMessageAsync(client, cancellationToken);
                }
                catch (Exception ex)
                {
                    // Don't throw, exceptions get squashed on this thread. Relay to client
                    client.SetException(ex);
                }
            } });
        }

        static async Task RunTasksAsync()
        {
            logger.Trace($"Global :{nameof(RunTasksAsync)} is starting");
            Task[] clientTasks;

            // Get initial Count and initialize clients
            await _internalSync.WaitAsync();
            InitiailizeNewTasks();
            _internalSync.Release();

            while (clientTasks.Length > 0)
            {
                var tasks = clientTasks.Union(new[] { _updateThread.Task });
                if(tasks.Any(x => x == null))
                {
                    Console.WriteLine("The Fuck");
                }
                var completedTask = await Task.WhenAny(tasks);

                // Set new count and initialize clients
                await _internalSync.WaitAsync();
                if (completedTask == _updateThread.Task)
                {
                    InitiailizeNewTasks();
                }
                else
                {
                    _clients.RemoveAll(x => x.Task == completedTask);
                    clientTasks = _clients.Where(x => x.Task != null).Select(x => x.Task).ToArray();
                }
                _internalSync.Release();
            }

            void InitiailizeNewTasks()
            {
                foreach (var clientTask in _clients)
                {
                    if (clientTask.Task == null)
                    {
                        clientTask.Task = clientTask.TaskFunction();
                    }
                }
                clientTasks = _clients.Select(x => x.Task).ToArray();
            }

            logger.Trace($"Global: {nameof(RunTasksAsync)} is ending");
        }

        private static async Task<string> ExchangeVersionAsync(SshClient client, CancellationToken cancellationToken)
        {
            await client.TcpConnection.ConnectAsync(client.ConnectionInfo.Hostname, client.ConnectionInfo.Port);
            var serverVersionFilter = new Regex(@"^SSH-(?<ProtoVersion>\d\.\d+)-(?<SoftwareVersion>\S+)(?<Comments>\s[^\r\n]+)?", RegexOptions.Compiled);

            // Send our version first.
            var clientVersionBytes = Encoding.UTF8.GetBytes(client.ConnectionInfo.ClientVersion + "\n");
            await client.TcpStream.WriteAsync(clientVersionBytes, 0, clientVersionBytes.Length, cancellationToken);
            await client.TcpStream.FlushAsync(cancellationToken);

            // Buffer to receive their version.
            var buffer = new byte[ushort.MaxValue];
            var bufferPosition = 0;

            while (client.TcpStream.CanRead)
            {
                if (bufferPosition == ushort.MaxValue)
                {
                    throw new ArgumentOutOfRangeException();
                }

                var readAmount = await client.TcpStream.ReadAsync(buffer, bufferPosition, 1, cancellationToken);
                if (readAmount <= 0)
                {
                    logger.Fatal($"{client.ConnectionInfo.Hostname} - { nameof(ExchangeVersionAsync)}: Read Amount: {readAmount}, BufferPosition: {bufferPosition}");
                    if(bufferPosition == 0)
                    {
                        logger.Fatal($"{client.ConnectionInfo.Hostname} - { nameof(ExchangeVersionAsync)}: Buffer Position is 0, no data sent. Possibly too many connections");
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

        private static async Task ReadMessageAsync(SshClient client, CancellationToken cancellationToken)
        {
            try
            {
                var sshPacket = await client.ConnectionInfo.ReadCryptoAlgorithm.ReadPacketAsync(client.TcpStream, cancellationToken);
                if (client.ConnectionInfo.ReadMacAlgorithm.OutputSize != 0)
                {
                    var messageAuthenticationHash = await client.TcpStream.ReadBytesAsync((uint)client.ConnectionInfo.ReadMacAlgorithm.OutputSize, cancellationToken);
                    if (!client.ConnectionInfo.ReadMacAlgorithm.VerifyMac(messageAuthenticationHash, client.ConnectionInfo.InboundPacketSequence, sshPacket))
                    {
                        throw new InvalidDataException("Received a malformed packet from host.");
                    }
                }

                client.ConnectionInfo.InboundPacketSequence = client.ConnectionInfo.InboundPacketSequence != uint.MaxValue ? client.ConnectionInfo.InboundPacketSequence + 1 : 0;
                var messageEvent = new MessageEvent(sshPacket.Payload);
                logger.Debug($"{client.ConnectionInfo.Hostname} - {nameof(ReadMessageAsync)}: Received {messageEvent.Type}");
                
                // Key Exchange Messages
                switch(messageEvent.Type)
                {
                    case MessageType.SSH_MSG_KEXINIT:
                        client.ConnectionInfo.KeyExchanger.SendMessage(messageEvent.Message as KexInit);
                        break;
                    case MessageType.SSH_MSG_NEWKEYS:
                        client.ConnectionInfo.SshNewKeysCompletion = new TaskCompletionSource<bool>();
                        client.ConnectionInfo.KeyExchanger.SendMessage(messageEvent.Message as NewKeys);
                        await client.ConnectionInfo.SshNewKeysCompletion.Task;
                        break;
                    case MessageType.SSH_MSG_KEX_Exchange_30:
                    case MessageType.SSH_MSG_KEX_Exchange_31:
                    case MessageType.SSH_MSG_KEX_Exchange_32:
                    case MessageType.SSH_MSG_KEX_Exchange_33:
                    case MessageType.SSH_MSG_KEX_Exchange_34:
                        client.ConnectionInfo.KeyExchanger.SendKeyExchangeMessage(messageEvent);
                        break;
                    case MessageType.SSH_MSG_SERVICE_ACCEPT:
                        client.ConnectionInfo.Authentication.SendMessage(messageEvent.Message as ServiceAccept);
                        break;
                    case MessageType.SSH_MSG_REQUEST_FAILURE:
                        client.ConnectionInfo.Authentication.SendRequestFailureMessage();
                        break;
                    case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                        client.ConnectionInfo.Authentication.SendMessage(messageEvent.Message as UaSuccess);
                        break;
                    case MessageType.SSH_MSG_USERAUTH_FAILURE:
                        client.ConnectionInfo.Authentication.SendMessage(messageEvent.Message as UaFailure);
                        break;
                    case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                        client.ConnectionInfo.Authentication.SendMessage(messageEvent.Message as UaInfoRequest);
                        break;
                    case MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                    case MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE:
                    case MessageType.SSH_MSG_CHANNEL_SUCCESS:
                    case MessageType.SSH_MSG_CHANNEL_FAILURE:
                    case MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                    case MessageType.SSH_MSG_CHANNEL_DATA:
                    case MessageType.SSH_MSG_CHANNEL_CLOSE:
                    case MessageType.SSH_MSG_CHANNEL_EOF:
                        logger.Debug($"Sending Channel Message to client");
                        await client.SendChannelMessageAsync(messageEvent, cancellationToken);
                        break;
                    default:
                        logger.Info($"{client.ConnectionInfo.Hostname} - {nameof(ReadMessageAsync)}: Unexpected Message {messageEvent.Type}");
                        break;
                }
                await AddClientTaskAsync(new ClientTask() { Client = client, TaskFunction = () => ReadMessageAsync(client, cancellationToken) });
            }
            catch (Exception ex)
            {
                // Don't throw, exceptions get squashed on this thread. Relay to client
                client.SetException(ex);
            }
            finally
            {
               // _readSemaphore.Release();
            }
        }

        internal static async Task WriteMessageAsync(SshClient client, IMessage message, CancellationToken cancellationToken)
        {
               // await _writeSemaphore.WaitAsync(_taskSourceCancellation.Token);
               // await Log($"Sending {message.Type}");

                var compressedPayload = client.ConnectionInfo.WriteCompressionAlgorithm.Compress(message.GetBytes());
                var sshPacket = new SshPacket(compressedPayload,
                        client.ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize > 8
                        ? client.ConnectionInfo.WriteCryptoAlgorithm.CipherBlockSize : 8);

                await client.TcpStream.WriteAsync(client.ConnectionInfo.WriteCryptoAlgorithm.Encrypt(sshPacket.Raw), cancellationToken);

                if (client.ConnectionInfo.WriteMacAlgorithm.OutputSize != 0)
                {
                    await client.TcpStream.WriteAsync(client.ConnectionInfo.WriteMacAlgorithm.ComputeHash(client.ConnectionInfo.OutboundPacketSequence,
                                sshPacket), cancellationToken);
                }

                await client.TcpStream.FlushAsync(cancellationToken);
                client.ConnectionInfo.OutboundPacketSequence = client.ConnectionInfo.OutboundPacketSequence != uint.MaxValue
                                                             ? client.ConnectionInfo.OutboundPacketSequence + 1
                                                             : 0;

            logger.Debug($"{client.ConnectionInfo.Hostname} - {nameof(WriteMessageAsync)}: Sent {message.Type}");

            // _writeSemaphore.Release();
        }

        public class ClientTask
        {
            public SshClient Client;
            public Func<Task> TaskFunction;
            public Task Task;
        }
    }
}
