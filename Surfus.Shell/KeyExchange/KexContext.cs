using System;
using Surfus.Shell.Authentication;

namespace Surfus.Shell.KeyExchange
{
    /// <summary>
    /// Carries the dependencies needed by key exchange algorithms,
    /// decoupling them from SshClient.
    /// </summary>
    internal class KexContext
    {
        internal SendMessageAsync Send { get; }
        internal SshMessageInbox Inbox { get; }
        internal string ClientVersion { get; }
        internal string ServerVersion { get; }
        internal Func<byte[], bool> HostKeyCallback { get; }

        /// <summary>
        /// Set by the key exchange algorithm after verifying the host key.
        /// </summary>
        internal byte[] ServerCertificate { get; set; }
        internal int ServerCertificateSize { get; set; }

        internal KexContext(SendMessageAsync send, SshMessageInbox inbox, string clientVersion, string serverVersion, Func<byte[], bool> hostKeyCallback)
        {
            Send = send;
            Inbox = inbox;
            ClientVersion = clientVersion;
            ServerVersion = serverVersion;
            HostKeyCallback = hostKeyCallback;
        }
    }
}
