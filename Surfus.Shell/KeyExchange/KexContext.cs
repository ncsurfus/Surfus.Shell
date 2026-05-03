using System;

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
        internal Func<byte[], bool> HostKeyCallback { get; }
        internal SshAlgorithms Algorithms { get; }
        internal byte[] ServerCertificate { get; set; }
        internal int ServerCertificateSize { get; set; }

        internal KexContext(SshMessageInbox inbox, string clientVersion, string serverVersion, Func<byte[], bool> hostKeyCallback, SshAlgorithms algorithms)
        {
            Inbox = inbox;
            ClientVersion = clientVersion;
            ServerVersion = serverVersion;
            HostKeyCallback = hostKeyCallback;
            Algorithms = algorithms;
        }
    }
}
