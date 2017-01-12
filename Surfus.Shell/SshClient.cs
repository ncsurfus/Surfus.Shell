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
            await ConnectTaskSource.Task;
        }

        internal void SetException(Exception ex)
        {
            if(!InternalCancellation.IsCancellationRequested)
            {
                InternalCancellation.Cancel();
            }
            if(IsFinished)
            {
                logger.Debug($"{ConnectionInfo.Hostname}:{ConnectionInfo.Port} (IsFinished:{IsFinished}): + {ex}");
            }
            logger.Fatal($"{ConnectionInfo.Hostname}:{ConnectionInfo.Port} (IsFinished:{IsFinished}): + {ex}");
            SetTaskExceptions(ex);
        }

        private void SetTaskExceptions(Exception ex)
        {
            ConnectTaskSource.TrySetException(ex);
        }

        public void Close()
        {
            _isDisposed = true;
            if(!_isDisposed)
            {
                TcpConnection.Close();
            }
        }

        public void Dispose()
        {
            Close();
        }
    }
}
