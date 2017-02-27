using System;
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
    public class SshTerminal
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        internal TaskCompletionSource<bool> ChannelOpenTaskSource;
        internal TaskCompletionSource<bool> ChannelCloseTaskSource;

        internal TaskCompletionSource<bool> PseudoTerminalTaskSource;
        internal TaskCompletionSource<bool> ShellTaskSource;
        internal TaskCompletionSource<bool> TerminalWriteTaskSource;
        internal TaskCompletionSource<bool> TerminalReadTaskSource;

        private readonly StringBuilder _readBuffer = new StringBuilder();
        private TaskCompletionSource<bool> _readCompletionSource = new TaskCompletionSource<bool>();
        private bool _shouldCloseClient = false;

        internal SshTerminal(SshClient sshClient, SshChannel channel)
        {
            SshClient = sshClient;
            Channel = channel;
            Channel.OnDataReceived = (buffer, cancellationToken) =>
            {
                _readBuffer.Append(Encoding.UTF8.GetString(buffer));
                _readCompletionSource?.TrySetResult(true);
                return Task.FromResult(true);
            };
            Channel.OnChannelCloseReceived = async (close, cancellationToken) =>
            {
                await CloseAsync(cancellationToken);
                ServerDisconnected?.Invoke();
            };
        }

        internal SshChannel Channel { get; }
        public SshClient SshClient { get; }
        public bool IsOpen => Channel.IsOpen;
        public bool DataAvailable => _readBuffer.Length > 0;

        public event Action ServerDisconnected;

        public async Task OpenAsync(CancellationToken cancellationToken)
        {
            if (ChannelOpenTaskSource != null || PseudoTerminalTaskSource != null || ShellTaskSource != null)
            {
                throw new SshException($"Terminal is already opening or opened.");
            }

            ChannelOpenTaskSource = new TaskCompletionSource<bool>();
            PseudoTerminalTaskSource = new TaskCompletionSource<bool>();
            ShellTaskSource = new TaskCompletionSource<bool>();

            CancellationTokenSource.CreateLinkedTokenSource(SshClient.InternalCancellation.Token, cancellationToken);

            cancellationToken.Register(() =>
            {
                ChannelOpenTaskSource.TrySetException(new TaskCanceledException(ChannelCloseTaskSource.Task));
                PseudoTerminalTaskSource.TrySetException(new TaskCanceledException(ChannelCloseTaskSource.Task));
                ShellTaskSource.TrySetException(new TaskCanceledException(ChannelCloseTaskSource.Task));
            });

            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = SshClient,
                TaskFunction = async () =>
                {
                    try
                    {
                        await Channel.OpenAsync(new ChannelOpenSession(Channel.ClientId, 50000), SshClient.InternalCancellation.Token);
                        await Channel.RequestAsync(new ChannelRequestPseudoTerminal(Channel.ServerId, true, "Surfus", 80, 24), SshClient.InternalCancellation.Token);
                        await Channel.RequestAsync(new ChannelRequestShell(Channel.ServerId, true), SshClient.InternalCancellation.Token);
                        ChannelOpenTaskSource.TrySetResult(true);
                        PseudoTerminalTaskSource.TrySetResult(true);
                        ShellTaskSource.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        ChannelOpenTaskSource.TrySetException(ex);
                        PseudoTerminalTaskSource.TrySetException(ex);
                        ShellTaskSource.TrySetException(ex);
                    }
                }
            });

            await ChannelOpenTaskSource.Task;
            await PseudoTerminalTaskSource.Task;
            await ShellTaskSource.Task;
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
                        await Channel.CloseAsync(SshClient.InternalCancellation.Token);
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

        public async Task WriteAsync(string text, CancellationToken cancellationToken)
        {
            if(TerminalWriteTaskSource != null)
            {
                throw new SshException("Terminal is already writing data.");
            }

            TerminalWriteTaskSource = new TaskCompletionSource<bool>();
            cancellationToken.Register(() => TerminalWriteTaskSource.TrySetException(new TaskCanceledException(TerminalWriteTaskSource.Task)));
            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = SshClient,
                TaskFunction = async () =>
                {
                    try
                    {
                        await Channel.WriteDataAsync(Encoding.UTF8.GetBytes(text), SshClient.InternalCancellation.Token);
                        TerminalWriteTaskSource.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        TerminalWriteTaskSource.TrySetException(ex);
                    }
                }
            });

            await TerminalWriteTaskSource.Task;
            TerminalWriteTaskSource = null; 
        }

        public async Task<string> ReadAsync()
        {
            return await ReadAsync(CancellationToken.None);
        }

        public async Task<string> ReadAsync(CancellationToken cancellationToken)
        {
            logger.Trace($"Entering {nameof(SshTerminal)} - {nameof(ReadAsync)}");
            if (TerminalReadTaskSource != null)
            {
                throw new SshException($"Terminal is already reading.");
            }

            if (ChannelCloseTaskSource != null)
            {
                throw new SshException($"Terminal is closed.");
            }

            if (ChannelOpenTaskSource == null || PseudoTerminalTaskSource == null || ShellTaskSource == null)
            {
                throw new SshException($"Terminal is not opened");
            }

            string text;
            if (_readBuffer.Length > 0)
            {
                text = _readBuffer.ToString();
            }
            else
            {
                TerminalReadTaskSource = new TaskCompletionSource<bool>();

                cancellationToken.Register(() => TerminalReadTaskSource?.TrySetCanceled());

                await _readCompletionSource.Task;
                _readCompletionSource = new TaskCompletionSource<bool>();

                _readCompletionSource = null;
                TerminalReadTaskSource = null;

                text = _readBuffer.ToString();
            }

            _readBuffer.Clear();
            return text;
        }
    }
}
