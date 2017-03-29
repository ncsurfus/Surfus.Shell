using System;
using System.Globalization;
using System.Numerics;

namespace Surfus.Shell.KeyExchange.DiffieHellman
{
    /// <summary>
    /// Implements the Diffie-Hellman Group14 Sha1 Exchange.
    /// </summary>
    internal sealed class DiffieHellmanGroup14Sha1 : DiffieHellmanKeyExchange
    {
        public DiffieHellmanGroup14Sha1(SshClient sshClient, KexInitExchangeResult kexInitExchangeResult)
            : base(sshClient, kexInitExchangeResult)
        {
            E = BigInteger.Zero;
			while (E < 1 || E > P - 1)
			{
				if (!sshClient.ConnectionInfo.ServerVersion.Contains("OpenSSH"))
				{
					X = GenerateRandomBigInteger(1, 4096);
					E = BigInteger.ModPow(G, X, P);
				}
				else
				{
					X = GenerateRandomBigInteger(2048, 4096);
					E = BigInteger.ModPow(G, X, P);
				}
            }
        }

        /// <summary>
        /// E = g^x mod p
        /// </summary>
        protected override BigInteger E { get; }

        /// <summary>
        /// A large predefined safe prime number.
        /// </summary>
        protected override BigInteger P { get; } =
            BigInteger.Parse(
                "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 
                NumberStyles.AllowHexSpecifier);

        /// <summary>
        /// A random number between [1, q]
        /// </summary>
        protected override BigInteger X { get; }
    }
}