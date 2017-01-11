using NLog;
using Surfus.Shell.Extensions;
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
                await ExchangeVersionAsync(client, cancellationToken);
            } });
        }

        static async Task RunTasksAsync()
        {
            int taskCount;

            // Get initial Count and initialize clients
            await _internalSync.WaitAsync();
            InitiailizeNewTasks();
            _internalSync.Release();

            while (taskCount > 0)
            {
                var completedTask = await Task.WhenAny(_clients.Select(x => x.Task).Union(new[] { _updateThread.Task }));

                // Set new count and initialize clients
                await _internalSync.WaitAsync();
                if (completedTask == _updateThread.Task)
                {
                    InitiailizeNewTasks();
                }
                else if (completedTask.Exception != null)
                {
                    logger.Error(completedTask.Exception.ToString());
                    _clients.RemoveAll(x => x.Task == completedTask);
                }
                else
                {
                    _clients.RemoveAll(x => x.Task == completedTask);
                }
                _internalSync.Release();
            }

            void InitiailizeNewTasks()
            {
                taskCount = _clients.Count;
                foreach (var clientTask in _clients)
                {
                    if (clientTask.Task == null)
                    {
                        clientTask.Task = clientTask.TaskFunction();
                    }
                }
            }
        }

        private static async Task ExchangeVersionAsync(SshClient client, CancellationToken cancellationToken)
        {
            try
            {
                await client.TcpConnection.ConnectAsync(client.ConnectionInfo.Hostname, client.ConnectionInfo.Port);
                var serverVersionFilter = new Regex(@"^SSH-(?<ProtoVersion>\d\.\d+)-(?<SoftwareVersion>\S+)(?<Comments>\s[^\r\n]+)?", RegexOptions.Compiled);

                // Send our version first.
                var clientVersionBytes = Encoding.UTF8.GetBytes(client.ConnectionInfo.ClientVersion + "\n");
                await client.TcpStream.WriteAsync(
                        clientVersionBytes,
                        0,
                        clientVersionBytes.Length, cancellationToken);
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
                        throw new EndOfStreamException();
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
                                client.ConnectionInfo.ServerVersion = serverVersion;
                                logger.Debug($"{client.ConnectionInfo.Hostname}:{clien.ConnectionInfot.Port}: {nameof(client.ConnectionInfo.ServerVersion)} is {client.ConnectionInfo.ServerVersion}");
                                client.ConnectTaskSource.TrySetResult(true);
                                return;
                            }
                        }

                        buffer = new byte[ushort.MaxValue];
                        bufferPosition = 0;
                    }
                    bufferPosition += readAmount;
                }

                
                throw new Exception("Invalid version from server");
            }
            catch (Exception ex)
            {
                logger.Error($"Exception at nameof(ExchangeVersionAsync): {ex}");
                client.ConnectTaskSource.TrySetException(ex);
                throw;
            }
        }

        private static async Task ReadMessageAsync(SshClient client, CancellationToken cancellationToken)
        {
            try
            {
                //await _readSemaphore.WaitAsync(_taskSourceCancellation.Token);
                var sshPacket = await client.ConnectionInfo.ReadCryptoAlgorithm.ReadPacketAsync(client.TcpStream, cancellationToken);
                if (client.ConnectionInfo.ReadMacAlgorithm.OutputSize != 0)
                {
                    var messageAuthenticationHash = await client.TcpStream.ReadBytesAsync((uint)client.ConnectionInfo.ReadMacAlgorithm.OutputSize, cancellationToken);
                    if (!client.ConnectionInfo.ReadMacAlgorithm.VerifyMac(messageAuthenticationHash, client.ConnectionInfo.InboundPacketSequence, sshPacket))
                    {
                        throw new InvalidDataException("Received a malformed packet from host.");
                    }
                }

                client.ConnectionInfo.InboundPacketSequence = client.ConnectionInfo.InboundPacketSequence != uint.MaxValue
                                                            ? client.ConnectionInfo.InboundPacketSequence + 1
                                                            : 0;
               // await OnMessageReceived(new MessageEvent(sshPacket.Payload));
            }
            catch (Exception ex) when (ex is IOException || ex is TaskCanceledException || ex is OperationCanceledException || ex is ObjectDisposedException)
            {
                throw new IOException("SSH connection was terminated.", ex);
            }
            finally
            {
               // _readSemaphore.Release();
            }
        }


        public class ClientTask
        {
            public SshClient Client;
            public Func<Task> TaskFunction;
            public Task Task;
        }
    }
}
