using NLog;
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

        // Task Completion Sources
        internal TaskCompletionSource<bool> ConnectTaskSource = new TaskCompletionSource<bool>();
        internal TaskCompletionSource<bool> LoginTaskSource = new TaskCompletionSource<bool>();
        internal TaskCompletionSource<string> LoginBannerTaskSource = new TaskCompletionSource<string>();

        // Network Connection
        internal TcpClient TcpConnection { get; } = new TcpClient();
        internal NetworkStream TcpStream => TcpConnection.GetStream();

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

        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            // If this cancels, we must cancel the TaskCompeletionSource and Background Thread...
            cancellationToken.Register(() => SetException(new TaskCanceledException(ConnectTaskSource.Task)));

            // Add the ConnectAsync delegate to the background thread.
            await SshClientStaticThread.ConnectAsync(this, InternalCancellation.Token);

            // Await the TaskCompeletionSource 
            await ConnectTaskSource.Task.ConfigureAwait(false);
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


        public async Task LoginAsync(string username, Func<string, Task<string>> InteractiveDelegate, CancellationToken cancellationToken)
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
                        // Don't throw, exceptions get squashed on this thread. Relay to client
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
            if (!IsFinished)
            {
                logger.Fatal($"{ConnectionInfo.Hostname}: {ex}");
            }
            else
            {
                logger.Debug($"{ConnectionInfo.Hostname} (After Fatal/Success): {ex.Message}");
            }
            SetTaskExceptions(ex);
            Close();
        }

        private void SetTaskExceptions(Exception ex)
        {
            // Throw exception on tasks on foreground thread
            ConnectTaskSource?.TrySetException(ex);

            // Cancel tasks on background thread
            ConnectionInfo.KeyExchanger?.KexInitMessage?.TrySetCanceled();
            ConnectionInfo.KeyExchanger?.NewKeysMessage?.TrySetCanceled();
        }

        public void Close()
        {
            if(!_isDisposed)
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
            Close();
        }
    }
}
