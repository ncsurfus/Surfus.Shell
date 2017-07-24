using System;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Extensions;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Crypto
{
    /// <summary>
    /// Implements a common core of methods for crypto algorithms.
    /// </summary>
    internal abstract class CryptoServiceProviderAlgorithm : CryptoAlgorithm
    {
        /// <summary>
        /// The crypto provider.
        /// </summary>
        private readonly SymmetricAlgorithm _cryptoProvider;

        /// <summary>
        /// The ICryptoTransform to decrypt the data.
        /// </summary>
        private ICryptoTransform _decryptor;

        /// <summary>
        /// The ICryptoTransform to encrypt the data.
        /// </summary>
        private ICryptoTransform _encryptor;

        /// <summary>
        /// Constructs the CryptoServiceProviderAlgorithm class.
        /// </summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        protected CryptoServiceProviderAlgorithm(SymmetricAlgorithm cryptoProvider)
        {
            _cryptoProvider = cryptoProvider;
        }

        /// <summary>
        /// Disposes the CryptoServiceProviderAlgorithm.
        /// </summary>
        public override void Dispose()
        {
            _encryptor?.Dispose();
            _decryptor?.Dispose();
            _cryptoProvider.Dispose();
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        /// <param name="byteArray">The data to encrypt.</param>
        /// <returns></returns>
        internal override ArraySegment<byte> Encrypt(byte[] byteArray, int offset, int length)
        {
            var encryptedBlocks = new byte[(length / _encryptor.InputBlockSize) * _encryptor.OutputBlockSize];
            var totalEncryptedBytes = _encryptor.TransformBlock(byteArray, offset, length, encryptedBlocks, 0);
            if (totalEncryptedBytes != encryptedBlocks.Length)
            {
                throw new Exception("Invalid byteArray encryption");
            }

            return new ArraySegment<byte>(encryptedBlocks);
        }

        /// <summary>
        /// Initializes the cipher. You must initialize the cipher before caling Encrypt or ReadPacket.
        /// </summary>
        /// <param name="initializationVector">The initialization vector for the cipher.</param>
        /// <param name="key">The key for the cipher.</param>
        internal override void Initialize(byte[] initializationVector, byte[] key)
        {
            var usableEncryptionKey = key.Take(KeySize).ToArray();
            var usableInitialIv = initializationVector.Take(InitializationVectorSize).ToArray();
            _encryptor = _cryptoProvider.CreateEncryptor(usableEncryptionKey, usableInitialIv);
            _decryptor = _cryptoProvider.CreateDecryptor(usableEncryptionKey, usableInitialIv);

            if (!_encryptor.CanTransformMultipleBlocks)
            {
                throw new Exception("Encryptor: CanTransformMultipleBlocks is not true!");
            }

            if (!_decryptor.CanTransformMultipleBlocks)
            {
                throw new Exception("Decryptor: CanTransformMultipleBlocks is not true!");
            }
        }

        internal override async Task<SshPacket> ReadPacketAsync(NetworkStream networkStream, uint packetSequenceNumber, int hmacSize, CancellationToken cancellationToken)
        {
            var blockSize = _decryptor.InputBlockSize; // This code was made assuming the decryption and encryption block sizes are the same!
            var expectedPacketSize = 128; // We're going to initialize the buffer to the average expected packet length.
            var buffer = new byte[4 + blockSize + expectedPacketSize + hmacSize];// Array Length: uint (packetSequenceNumber) + uint (packet size) + expectedPacketSize + hmac size

            ByteWriter.WriteUint(buffer, 0, packetSequenceNumber); // Write first uint, which is the packet sequence number.
            var packetStart = 4; // This is where we actually start adding packet data, skipping the provided packet sequence number..
            var bufferPosition = 4; // Tracks where we last wrote data into our buffer.

            // Read enough data until we have at least 1 block.
            while (bufferPosition != blockSize + packetStart)
            {
                bufferPosition += await networkStream.ReadAsync(buffer, bufferPosition, blockSize + packetStart - bufferPosition, cancellationToken);
            }

            _decryptor.TransformBlock(buffer, bufferPosition - blockSize, blockSize, buffer, bufferPosition - blockSize); // Decrypt the first block in the buffer.

            var sshPacketSize = ByteReader.ReadUInt32(buffer, 4); // Get the length of the packet.
            if (sshPacketSize > 35000) throw new SshException("Invalid message sent, packet was to large!");
            int bufferLength = (int)(4 + 4 + sshPacketSize + hmacSize); // Calculate the full size of what our buffer *should* be. uint (packetSequenceNumber) + uint (packet size) + packet + hmac size

            if (buffer.Length < bufferLength) // Check to see if we need a bigger buffer and should allocate additional data.
            {
                Array.Resize(ref buffer, bufferLength);
            }

            while (bufferPosition != bufferLength) // Read the rest of the data from the buffer. This loop may not even run if we've already read everything..
            {
                bufferPosition += await networkStream.ReadAsync(buffer, bufferPosition, bufferLength - bufferPosition, cancellationToken);
            }

            if(sshPacketSize > blockSize) // Check if this was more than a single block..
            {
                // Decrypt everything except the first block as that was already decrypted!
                _decryptor.TransformBlock(buffer, 4 + blockSize, bufferLength - 4 - blockSize - hmacSize, buffer, 4 + blockSize);
            }

            return new SshPacket(buffer, 4, bufferLength - 4 - hmacSize);
        }
    }
}