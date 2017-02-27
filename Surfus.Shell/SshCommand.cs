using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;
using NLog;

namespace Surfus.Shell
{
    public class SshCommand
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        private readonly MemoryStream _memoryStream = new MemoryStream();
        internal TaskCompletionSource<bool> ExecuteTaskSource;
        internal TaskCompletionSource<bool> ExecuteEofTaskSource;
        internal TaskCompletionSource<bool> ExecuteCloseTaskSource;


        internal TaskCompletionSource<bool> ChannelOpenTaskSource;
        internal TaskCompletionSource<bool> ChannelCloseTaskSource;

        internal SshCommand(SshClient sshClient, SshChannel channel)
        {
            SshClient = sshClient;
            ChannelManager = channel;
            ChannelManager.OnDataReceived += (buffer, cancellationToken) =>
            {
                _memoryStream.Write(buffer, 0, buffer.Length);
                return Task.FromResult(true);
            };
        }

        internal SshChannel ChannelManager { get;}
        public SshClient SshClient { get; }
        public bool IsOpen => ChannelManager?.IsOpen ?? false;

        public async Task OpenAsync(CancellationToken cancellationToken)
        {
            if(ChannelOpenTaskSource != null)
            {
                throw new SshException($"OpenAsync has already been called on SshChannel");
            }
            ChannelOpenTaskSource = new TaskCompletionSource<bool>();

            cancellationToken.Register(() => SshClient.SetException(new TaskCanceledException(ChannelOpenTaskSource.Task)));
            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = SshClient,
                TaskFunction = async () =>
                {
                    try
                    {
                        await ChannelManager.OpenAsync(new ChannelOpenSession(ChannelManager.ClientId, 50000), SshClient.InternalCancellation.Token);
                        ChannelOpenTaskSource.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        ChannelOpenTaskSource.TrySetException(ex);
                    }
                }
            });

            await ChannelOpenTaskSource.Task;
        }

        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (ChannelCloseTaskSource != null)
            {
                throw new SshException($"SshCommand is already closed or closing.");
            }
            ChannelCloseTaskSource = new TaskCompletionSource<bool>();

            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = SshClient,
                TaskFunction = async () =>
                {
                    try
                    {
                        await ChannelManager.CloseAsync(SshClient.InternalCancellation.Token);
                        ChannelCloseTaskSource.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        ChannelCloseTaskSource.TrySetException(ex);
                    }
                }
            });

            await ChannelCloseTaskSource.Task;
        }

        public async Task<string> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            if (ChannelOpenTaskSource?.Task.IsCompleted != true)
            {
                throw new SshException("Channel not opened.");
            }

            if (ChannelCloseTaskSource?.Task.IsCompleted == true)
            {
                throw new SshException("Channel closed.");
            }

            if (ExecuteTaskSource != null || ExecuteEofTaskSource != null || ExecuteCloseTaskSource != null)
            {
                throw new SshException("Command ExecuteAsync already in progress.");
            }

            ExecuteTaskSource = new TaskCompletionSource<bool>();
            ExecuteCloseTaskSource = new TaskCompletionSource<bool>();
            ExecuteEofTaskSource = new TaskCompletionSource<bool>();
            ChannelManager.OnChannelEofReceived = (message, token) => { ExecuteEofTaskSource.SetResult(true); return Task.FromResult(true); };
            ChannelManager.OnChannelCloseReceived = (message, token) => { ExecuteCloseTaskSource.SetResult(true); return Task.FromResult(true); };

            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = SshClient,
                TaskFunction = async () =>
                {
                    try
                    {
                        await ChannelManager.RequestAsync(new ChannelRequestExec(ChannelManager.ServerId, true, command), SshClient.InternalCancellation.Token);
                        await ExecuteEofTaskSource.Task;
                        await ExecuteCloseTaskSource.Task;
                        ExecuteTaskSource.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        ExecuteCloseTaskSource.TrySetException(ex);
                        ExecuteEofTaskSource.TrySetException(ex);
                        ExecuteTaskSource.TrySetException(ex);
                    }
                }
            });

            await ExecuteTaskSource.Task;
            using (_memoryStream)
            {
                ExecuteCloseTaskSource = null;
                ExecuteEofTaskSource = null;
                ExecuteTaskSource = null;
                return Encoding.UTF8.GetString(_memoryStream.ToArray());
            }
        }
    }
}
