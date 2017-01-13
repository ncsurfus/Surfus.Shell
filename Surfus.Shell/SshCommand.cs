using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;

namespace Surfus.Shell
{
    public class SshCommand
    {
        private readonly MemoryStream _memoryStream = new MemoryStream();

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
            TaskCompletionSource<bool> OpenTaskSource = new TaskCompletionSource<bool>();
            cancellationToken.Register(() => SshClient.SetException(new TaskCanceledException(OpenTaskSource.Task)));

            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = SshClient,
                TaskFunction = async () =>
                {
                    try
                    {
                        await ChannelManager.OpenAsync(new ChannelOpenSession(ChannelManager.ClientId, 50000), SshClient.InternalCancellation.Token);
                        OpenTaskSource.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        OpenTaskSource.TrySetException(ex);
                    }
                }
            });

            await OpenTaskSource.Task;
        }

        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            TaskCompletionSource<bool> CloseTaskSource = new TaskCompletionSource<bool>();

            cancellationToken.Register(() => SshClient.SetException(new TaskCanceledException(CloseTaskSource.Task)));

            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = SshClient,
                TaskFunction = async () =>
                {
                    try
                    {
                        await ChannelManager.CloseAsync(SshClient.InternalCancellation.Token);
                        CloseTaskSource.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        CloseTaskSource.TrySetException(ex);
                    }
                }
            });

            await CloseTaskSource.Task;
        }

        public async Task<string> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            if (!ChannelManager.IsOpen)
            {
                throw new SshException("Channel not opened.");
            }

            TaskCompletionSource<bool> ExecuteTaskSource = new TaskCompletionSource<bool>();
            TaskCompletionSource<bool> EofTaskSource = new TaskCompletionSource<bool>();
            TaskCompletionSource<bool> CloseTaskSource = new TaskCompletionSource<bool>();

            cancellationToken.Register(() => SshClient.SetException(new TaskCanceledException(ExecuteTaskSource.Task)));

            ChannelManager.OnChannelEofReceived = (message, token) => { EofTaskSource.SetResult(true); return Task.FromResult(true); };
            ChannelManager.OnChannelCloseReceived = (message, token) => { CloseTaskSource.SetResult(true); return Task.FromResult(true); };

            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = SshClient,
                TaskFunction = async () =>
                {
                    try
                    {
                        await ChannelManager.RequestAsync(new ChannelRequestExec(ChannelManager.ServerId, true, command), SshClient.InternalCancellation.Token);
                        await EofTaskSource.Task;
                        await CloseTaskSource.Task;
                        ExecuteTaskSource.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        CloseTaskSource.TrySetException(ex);
                        EofTaskSource.TrySetException(ex);
                        ExecuteTaskSource.TrySetException(ex);
                    }
                }
            });

            await ExecuteTaskSource.Task;
            if (_memoryStream?.Length > 0)
            {
                using (_memoryStream)
                {
                    return Encoding.UTF8.GetString(_memoryStream.ToArray());
                }
            }
            _memoryStream?.Dispose();
            throw new SshException("An error happened?");
        }
    }
}
