﻿using System.Globalization;
using System.Numerics;

namespace Surfus.Shell.KeyExchange.DiffieHellman
{
    /// <summary>
    /// Implements the Diffie-Hellman Group2 Sha1 Exchange. In the context of SSH this is known as Group1.
    /// </summary>
    internal sealed class DiffieHellmanGroup1Sha1 : DiffieHellmanKeyExchange
    {
        internal DiffieHellmanGroup1Sha1(SshClient sshClient, KexInitExchangeResult kexInitExchangeResult)
            : base(sshClient, kexInitExchangeResult)
        {
            E = BigInteger.Zero;
            while (E < 1 || E > P - 1)
            {
				if (!sshClient.ConnectionInfo.ServerVersion.Contains("OpenSSH"))
				{
					X = GenerateRandomBigInteger(1, 2048);
					E = BigInteger.ModPow(G, X, P);
				}
				else
				{
					X = GenerateRandomBigInteger(1024, 2048);
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
                "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 
                NumberStyles.AllowHexSpecifier);

        /// <summary>
        /// A random number between [1, q]
        /// </summary>
        protected override BigInteger X { get; }
    }
}