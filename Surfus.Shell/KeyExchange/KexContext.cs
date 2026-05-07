using System;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.KeyExchange
{
    /// <summary>
    /// Carries the dependencies needed by key exchange algorithms,
    /// decoupling them from SshClient.
    /// </summary>
    public class KexContext
    {
        internal SshMessageInbox Inbox { get; }
        internal string ClientVersion { get; }
        internal string ServerVersion { get; }
        internal Func<ReadOnlyMemory<byte>, CancellationToken, Task<bool>> HostKeyCallback { get; }
        internal SshAlgorithms Algorithms { get; }
        internal ReadOnlyMemory<byte> ServerCertificate { get; set; }
        internal int ServerCertificateSize { get; set; }

        internal KexContext(
            SshMessageInbox inbox,
            string clientVersion,
            string serverVersion,
            Func<ReadOnlyMemory<byte>, CancellationToken, Task<bool>> hostKeyCallback,
            SshAlgorithms algorithms
        )
        {
            Inbox = inbox;
            ClientVersion = clientVersion;
            ServerVersion = serverVersion;
            HostKeyCallback = hostKeyCallback;
            Algorithms = algorithms;
        }
    }
}
