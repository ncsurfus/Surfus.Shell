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
    public class SshClient
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        // Task Completion Sources
        internal TaskCompletionSource<bool> ConnectTaskSource = new TaskCompletionSource<bool>();

        // Network Connection
        internal TcpClient TcpConnection { get; } = new TcpClient();
        internal NetworkStream TcpStream => TcpConnection.GetStream();

        // Connection Info
        public SshConnectionInfo ConnectionInfo = new SshConnectionInfo();

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
            await SshClientStaticThread.ConnectAsync(this, cancellationToken);
            await ConnectTaskSource.Task;
        }
    }
}
