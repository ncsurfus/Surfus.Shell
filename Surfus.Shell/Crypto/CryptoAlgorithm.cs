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
    public abstract class CryptoAlgorithm : IDisposable
    {
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
        internal abstract void Encrypt(byte[] plainText, int offset, int length);

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
        internal abstract Task<SshPacket> ReadPacketAsync(
            NetworkStream networkStream,
            uint packetSequenceNumber,
            int hmacSize,
            CancellationToken cancellationToken
        );
    }
}
