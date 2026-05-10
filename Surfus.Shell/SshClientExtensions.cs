using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;

namespace Surfus.Shell
{
    public static class SshClientExtensions
    {
        /// <summary>
        /// Opens a terminal session on the SSH server.
        /// </summary>
        public static async Task<SshTerminal> CreateTerminalAsync(this SshClient client, CancellationToken cancellationToken, TerminalOptions? options = null)
        {
            var channel = await client.OpenChannelAsync(new ChannelOpenSession(0, 50000), cancellationToken).ConfigureAwait(false);
            var terminal = new SshTerminal(channel, options);
            await terminal.RequestAsync(cancellationToken).ConfigureAwait(false);
            return terminal;
        }

        /// <summary>
        /// Opens a command execution channel on the SSH server.
        /// </summary>
        public static async Task<SshCommand> CreateCommandAsync(this SshClient client, CancellationToken cancellationToken, bool combineStderr = false)
        {
            var channel = await client.OpenChannelAsync(new ChannelOpenSession(0, 50000), cancellationToken).ConfigureAwait(false);
            channel.CombineStderr = combineStderr;
            return new SshCommand(channel) { CombineStderr = combineStderr };
        }

        /// <summary>
        /// Opens a direct-tcpip channel to the specified remote host and port through the SSH server.
        /// </summary>
        public static Task<SshChannel> CreateDirectTcpIpChannelAsync(
            this SshClient client,
            string remoteHost,
            uint remotePort,
            CancellationToken cancellationToken,
            string originatorAddress = "127.0.0.1",
            uint originatorPort = 0)
        {
            return client.OpenChannelAsync(
                new ChannelOpenDirectTcpIp(remoteHost, remotePort, originatorAddress, originatorPort, 0),
                cancellationToken);
        }

        /// <summary>
        /// Listens on a local TCP port and forwards each accepted connection through the SSH server
        /// to the specified remote host and port. Runs until the cancellation token is triggered.
        /// Returns when cancelled; does not throw <see cref="OperationCanceledException"/>.
        /// </summary>
        public static async Task ForwardLocalPortAsync(
            this SshClient client,
            int localPort,
            string remoteHost,
            uint remotePort,
            CancellationToken cancellationToken,
            IPAddress? localAddress = null)
        {
            localAddress ??= IPAddress.Loopback;
            var listener = new TcpListener(localAddress, localPort);
            listener.Start();
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                    _ = ForwardConnectionAsync(client, tcpClient, remoteHost, remotePort, cancellationToken);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
            finally
            {
                listener.Stop();
            }
        }

        private static async Task ForwardConnectionAsync(
            SshClient client,
            TcpClient tcpClient,
            string remoteHost,
            uint remotePort,
            CancellationToken cancellationToken)
        {
            try
            {
                await using var channel = await client.CreateDirectTcpIpChannelAsync(remoteHost, remotePort, cancellationToken).ConfigureAwait(false);
                var networkStream = tcpClient.GetStream();

                var localToRemote = networkStream.CopyToAsync(channel.StandardInput, cancellationToken);
                var remoteToLocal = channel.StandardOutput.CopyToAsync(networkStream, cancellationToken);

                var completed = await Task.WhenAny(localToRemote, remoteToLocal).ConfigureAwait(false);
                await completed.ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (SshException) { }
            finally
            {
                tcpClient.Dispose();
            }
        }
    }
}
