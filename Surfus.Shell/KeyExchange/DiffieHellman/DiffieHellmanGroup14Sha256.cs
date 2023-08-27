using System.Security.Cryptography;

namespace Surfus.Shell.KeyExchange.DiffieHellman
{
    /// <summary>
    /// Implements the Diffie-Hellman Group14 Sha256 Exchange.
    /// </summary>
    internal sealed class DiffieHellmanGroup14Sha256 : DiffieHellmanGroup14Sha1
    {
        internal DiffieHellmanGroup14Sha256(SshClient sshClient, KexInitExchangeResult kexInitExchangeResult)
            : base(sshClient, kexInitExchangeResult) { }

        protected override HashAlgorithm CreateHashAlgorithm()
        {
            return SHA256.Create();
        }
    }
}
