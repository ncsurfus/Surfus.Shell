using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Crypto
{
    /// <summary>
    /// The base class for all crypto algorithms.
    /// </summary>
    internal abstract class CryptoAlgorithm : IDisposable
    {
        /// <summary>
        /// Supported crypto algorithms.
        /// </summary>
        internal static string[] Supported => new[] { "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc" };

        /// <summary>
        /// Gets the size of the cipher block.
        /// </summary>
        internal abstract int CipherBlockSize { get; }

        /// <summary>
        /// Gets the size of the Initialization Vector.
        /// </summary>
        internal abstract int InitializationVectorSize { get; }

        /// <summary>
        /// Gets the key size.
        /// </summary>
        internal abstract int KeySize { get; }

        /// <summary>
        /// Creates the specified crypto algorithm.
        /// </summary>
        /// <param name="name">
        /// The name of the crypto algorithm.
        /// </param>
        internal static CryptoAlgorithm Create(string name)
        {
            switch (name)
            {
                case "3des-cbc":
                    return new TripleDesCryptoAlgorithm();
                case "aes128-cbc":
                    return new AesCryptoAlgorithm(128, CipherMode.CBC);
                case "aes192-cbc":
                    return new AesCryptoAlgorithm(192, CipherMode.CBC);
                case "aes256-cbc":
                    return new AesCryptoAlgorithm(256, CipherMode.CBC);
				case "aes128-ctr":
					return new AesCtrCryptoAlgorithm(128);
				case "aes192-ctr":
					return new AesCtrCryptoAlgorithm(192);
				case "aes256-ctr":
					return new AesCtrCryptoAlgorithm(256);
                default:
                    throw new SshException("Crypto algorithm not supported");
            }
        }

        /// <summary>
        /// Disposes the crypto algorithm.
        /// </summary>
        public abstract void Dispose();

        /// <summary>
        /// Encrypts the data
        /// </summary>
        /// <param name="plainText">
        /// The data to be encrypted
        /// </param>
        /// <returns>The encrypted data</returns>
        internal abstract ArraySegment<byte> Encrypt(byte[] plainText, int offset, int length);

        /// <summary>
        /// Initializes the cipher. You must initialize the cipher before caling Encrypt or ReadPacket.
        /// </summary>
        /// <param name="initializationVector">The initialization vector for the cipher.</param>
        /// <param name="key">The key for the cipher.</param>
        internal abstract void Initialize(byte[] initializationVector, byte[] key);

        /// <summary>
        /// Decrypts the next packet in the network stream.
        /// </summary>
        /// <param name="networkStream">
        /// The network stream to decrypt the packet from.
        /// </param>
        /// <param name="cancellationToken">
        /// The cancellation token associated with the async method.
        /// </param>
        /// <returns>
        /// The SSH Packet.
        /// </returns>
        internal abstract Task<SshPacket> ReadPacketAsync(NetworkStream networkStream, int macSize, CancellationToken cancellationToken);
    }
}