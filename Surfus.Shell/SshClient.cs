using NLog;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    public class SshClient : IDisposable
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        // Client Semaphore
        internal SemaphoreSlim SshClientSemaphore = new SemaphoreSlim(1,1);

        // Task Completion Sources
        internal TaskCompletionSource<bool> ConnectTaskSource = new TaskCompletionSource<bool>();
        internal TaskCompletionSource<bool> LoginTaskSource = new TaskCompletionSource<bool>();
        internal TaskCompletionSource<string> LoginBannerTaskSource = new TaskCompletionSource<string>();

        // Network Connection
        internal TcpClient TcpConnection { get; } = new TcpClient();
        internal NetworkStream TcpStream => TcpConnection.GetStream();

        // Channels
        uint _channelCounter = 0;
        internal List<SshChannel> Channels = new List<SshChannel>();
        internal List<SshCommand> Commands = new List<SshCommand>();
        internal List<SshTerminal> Terminals = new List<SshTerminal>();

        // Internal CancellationToken
        internal CancellationTokenSource InternalCancellation = new CancellationTokenSource();

        // Connection Info
        public SshConnectionInfo ConnectionInfo = new SshConnectionInfo();

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

        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            // If this cancels, we must cancel the TaskCompeletionSource and Background Thread...
            cancellationToken.Register(() => SetException(new TaskCanceledException(ConnectTaskSource.Task)));

            // Add the ConnectAsync delegate to the background thread.
            await SshClientStaticThread.ConnectAsync(this, InternalCancellation.Token);

            // Await the TaskCompeletionSource 
            await ConnectTaskSource.Task;
        }

        public async Task LoginAsync(string username, string password, CancellationToken cancellationToken)
        {
            LoginTaskSource = new TaskCompletionSource<bool>();

            // If this cancels, we must cancel the TaskCompeletionSource and Background Thread...
            cancellationToken.Register(() => SetException(new TaskCanceledException(LoginTaskSource.Task)));
            if (ConnectionInfo.Authentication == null)
            {
                ConnectionInfo.Authentication = new SshAuthentication(this);
            }

            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = this,
                TaskFunction = async () =>
                {
                    try
                    {
                        await ConnectionInfo.Authentication.LoginAsync(username, password, InternalCancellation.Token);
                    }
                    catch (Exception ex)
                    {
                        // Login exceptions aren't critical
                        LoginTaskSource.TrySetException(ex);
                    }
                }
            });

            await LoginTaskSource.Task;
        }

        public async Task LoginAsync(string username, Func<string, CancellationToken, Task<string>> InteractiveDelegate, CancellationToken cancellationToken)
        {
            LoginTaskSource = new TaskCompletionSource<bool>();

            // If this cancels, we must cancel the TaskCompeletionSource and Background Thread...
            cancellationToken.Register(() => SetException(new TaskCanceledException(LoginTaskSource.Task)));
            if (ConnectionInfo.Authentication == null)
            {
                ConnectionInfo.Authentication = new SshAuthentication(this);
            }

            await SshClientStaticThread.AddClientTaskAsync(new SshClientStaticThread.ClientTask
            {
                Client = this,
                TaskFunction = async () =>
                {
                    try
                    {
                        await ConnectionInfo.Authentication.LoginInteractiveAsync(username, InteractiveDelegate, InternalCancellation.Token);
                    }
                    catch (Exception ex)
                    {
                        // Login exceptions aren't critical
                        LoginTaskSource.TrySetException(ex);
                    }
                }
            });

            await LoginTaskSource.Task;
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

        public void Close()
        {
            Close(nameof(Close));
        }

        internal void Close(string reason)
        {
            logger.Trace($"{ConnectionInfo.Hostname}: Entering {nameof(Close)} - {reason}");
            if (!_isDisposed)
            {
                logger.Debug($"{ConnectionInfo.Hostname}: Canceling Tasks.");
                InternalCancellation.Cancel(true);

                logger.Debug($"{ConnectionInfo.Hostname}: Disposing Stream. Expect ObjectDisposedExceptions.");
                TcpConnection.Dispose();
            }
            _isDisposed = true;
        }

        public void Dispose()
        {
            Close(nameof(Dispose));
        }
    }
}
