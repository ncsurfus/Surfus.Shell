using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Crypto
{
    /// <summary>
    /// Implements a common core of methods for crypto algorithms.
    /// </summary>
    public abstract class CryptoServiceProviderAlgorithm : CryptoAlgorithm
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
        internal override void Encrypt(byte[] byteArray, int offset, int length)
        {
            _encryptor.TransformBlock(byteArray, offset, length, byteArray, offset);
        }

        internal override void Decrypt(byte[] byteArray, int offset, int length)
        {
            _decryptor.TransformBlock(byteArray, offset, length, byteArray, offset);
        }

        /// <summary>
        /// Initializes the cipher. You must initialize the cipher before caling Encrypt or ReadPacket.
        /// </summary>
        /// <param name="initializationVector">The initialization vector for the cipher.</param>
        /// <param name="key">The key for the cipher.</param>
        internal override void Initialize(byte[] initializationVector, byte[] key)
        {
            var usableEncryptionKey = key.AsSpan(0, KeySize).ToArray();
            var usableInitialIv = initializationVector.AsSpan(0, InitializationVectorSize).ToArray();
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

        internal override async Task<SshPacket> ReadPacketAsync(
            NetworkStream networkStream,
            uint packetSequenceNumber,
            int hmacSize,
            bool isEtm,
            CancellationToken cancellationToken
        )
        {
            if (isEtm)
            {
                return await ReadPacketEtmAsync(networkStream, packetSequenceNumber, hmacSize, cancellationToken).ConfigureAwait(false);
            }

            var blockSize = _decryptor.InputBlockSize;
            var expectedPacketSize = 128;
            var buffer = new byte[4 + blockSize + expectedPacketSize + hmacSize];

            ByteWriter.WriteUint(buffer.AsSpan(0), packetSequenceNumber); // Write first uint, which is the packet sequence number.
            var packetStart = 4; // This is where we actually start adding packet data, skipping the provided packet sequence number..
            var bufferPosition = 4; // Tracks where we last wrote data into our buffer.

            // Read enough data until we have at least 1 block.
            while (bufferPosition != blockSize + packetStart)
            {
                var bytesRead = await networkStream.ReadAsync(
                    buffer.AsMemory(bufferPosition, blockSize + packetStart - bufferPosition),
                    cancellationToken
                );
                if (bytesRead == 0)
                {
                    throw new SshException("Connection closed.");
                }
                bufferPosition += bytesRead;
            }

            _decryptor.TransformBlock(buffer, bufferPosition - blockSize, blockSize, buffer, bufferPosition - blockSize); // Decrypt the first block in the buffer.

            var sshPacketSize = ByteReader.ReadUInt32(buffer.AsSpan(4)); // Get the length of the packet.
            if (sshPacketSize > 35000)
            {
                throw new SshException("Invalid message sent, packet was to large!");
            }
            int bufferLength = (int)(4 + 4 + sshPacketSize + hmacSize); // Calculate the full size of what our buffer *should* be. uint (packetSequenceNumber) + uint (packet size) + packet + hmac size

            if (buffer.Length < bufferLength) // Check to see if we need a bigger buffer and should allocate additional data.
            {
                Array.Resize(ref buffer, bufferLength);
            }

            while (bufferPosition != bufferLength) // Read the rest of the data from the buffer. This loop may not even run if we've already read everything..
            {
                var bytesRead = await networkStream.ReadAsync(
                    buffer.AsMemory(bufferPosition, bufferLength - bufferPosition),
                    cancellationToken
                );
                if (bytesRead == 0)
                {
                    throw new SshException("Connection closed.");
                }
                bufferPosition += bytesRead;
            }

            if (sshPacketSize > blockSize) // Check if this was more than a single block..
            {
                // Decrypt everything except the first block as that was already decrypted!
                _decryptor.TransformBlock(buffer, 4 + blockSize, bufferLength - 4 - blockSize - hmacSize, buffer, 4 + blockSize);
            }

            return new SshPacket(buffer, 4, bufferLength - 4 - hmacSize);
        }

        private async Task<SshPacket> ReadPacketEtmAsync(
            NetworkStream networkStream,
            uint packetSequenceNumber,
            int hmacSize,
            CancellationToken cancellationToken
        )
        {
            // ETM: packet length is plaintext, body is encrypted, MAC covers seq + length + ciphertext.
            var buffer = new byte[4 + 4 + 128 + hmacSize]; // seq(4) + length(4) + estimated body + hmac

            ByteWriter.WriteUint(buffer.AsSpan(0), packetSequenceNumber);
            var bufferPosition = 4;

            // Read the 4-byte plaintext packet length.
            while (bufferPosition < 8)
            {
                var bytesRead = await networkStream.ReadAsync(buffer.AsMemory(bufferPosition, 8 - bufferPosition), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    throw new SshException("Connection closed.");
                }
                bufferPosition += bytesRead;
            }

            var sshPacketSize = ByteReader.ReadUInt32(buffer.AsSpan(4));
            if (sshPacketSize > 35000)
            {
                throw new SshException("Invalid message sent, packet was too large!");
            }

            int bufferLength = (int)(4 + 4 + sshPacketSize + hmacSize);
            if (buffer.Length < bufferLength)
            {
                Array.Resize(ref buffer, bufferLength);
            }

            // Read encrypted body + MAC.
            while (bufferPosition < bufferLength)
            {
                var bytesRead = await networkStream.ReadAsync(buffer.AsMemory(bufferPosition, bufferLength - bufferPosition), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    throw new SshException("Connection closed.");
                }
                bufferPosition += bytesRead;
            }

            // Return packet with ciphertext intact — MAC verification happens in SshClient before decryption.
            // SshPacket.Length = 4 (packet_length) + sshPacketSize, so MAC is at offset Length+4.
            return new SshPacket(buffer, 4, (int)(4 + sshPacketSize));
        }
    }
}
