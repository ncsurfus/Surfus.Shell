using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
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
        private ICryptoTransform? _decryptor;

        /// <summary>
        /// The ICryptoTransform to encrypt the data.
        /// </summary>
        private ICryptoTransform? _encryptor;

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
            _encryptor!.TransformBlock(byteArray, offset, length, byteArray, offset);
        }

        internal override void Decrypt(byte[] byteArray, int offset, int length)
        {
            _decryptor!.TransformBlock(byteArray, offset, length, byteArray, offset);
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
            Stream stream,
            uint packetSequenceNumber,
            int hmacSize,
            bool isEtm,
            CancellationToken cancellationToken
        )
        {
            if (isEtm)
            {
                return await ReadPacketEtmAsync(stream, packetSequenceNumber, hmacSize, cancellationToken).ConfigureAwait(false);
            }

            var blockSize = _decryptor!.InputBlockSize;

            // Read the first encrypted block to determine packet length.
            var firstBlock = ArrayPool<byte>.Shared.Rent(blockSize);
            try
            {
                var firstBlockPos = 0;
                while (firstBlockPos < blockSize)
                {
                    var bytesRead = await stream.ReadAsync(
                        firstBlock.AsMemory(firstBlockPos, blockSize - firstBlockPos),
                        cancellationToken
                    );
                    if (bytesRead == 0)
                    {
                        throw new SshException("Connection closed.");
                    }
                    firstBlockPos += bytesRead;
                }

                _decryptor.TransformBlock(firstBlock, 0, blockSize, firstBlock, 0);

                var sshPacketSize = BinaryPrimitives.ReadUInt32BigEndian(firstBlock.AsSpan(0));
                if (sshPacketSize > 35000)
                {
                    throw new SshException("Invalid message sent, packet was too large!");
                }

                int bufferLength = (int)(4 + 4 + sshPacketSize + hmacSize);
                var buffer = ArrayPool<byte>.Shared.Rent(bufferLength);

                // Write sequence number and copy decrypted first block.
                ByteWriter.WriteUint(buffer.AsSpan(0), packetSequenceNumber);
                firstBlock.AsSpan(0, blockSize).CopyTo(buffer.AsSpan(4));
                var bufferPosition = 4 + blockSize;

                // Read remaining data.
                while (bufferPosition < bufferLength)
                {
                    var bytesRead = await stream.ReadAsync(
                        buffer.AsMemory(bufferPosition, bufferLength - bufferPosition),
                        cancellationToken
                    );
                    if (bytesRead == 0)
                    {
                        throw new SshException("Connection closed.");
                    }
                    bufferPosition += bytesRead;
                }

                // Decrypt remaining blocks (first block already decrypted).
                var remainingCiphertext = bufferLength - 4 - blockSize - hmacSize;
                if (remainingCiphertext > 0)
                {
                    _decryptor.TransformBlock(buffer, 4 + blockSize, remainingCiphertext, buffer, 4 + blockSize);
                }

                return new SshPacket(buffer, 4, bufferLength - 4 - hmacSize, pooled: true);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(firstBlock);
            }
        }

        private async Task<SshPacket> ReadPacketEtmAsync(
            Stream stream,
            uint packetSequenceNumber,
            int hmacSize,
            CancellationToken cancellationToken
        )
        {
            // ETM: packet length is plaintext, body is encrypted, MAC covers seq + length + ciphertext.
            // Read the 4-byte plaintext packet length into a small rented buffer.
            var lengthBuf = ArrayPool<byte>.Shared.Rent(4);
            uint sshPacketSize;
            try
            {
                var lengthPos = 0;
                while (lengthPos < 4)
                {
                    var bytesRead = await stream.ReadAsync(lengthBuf.AsMemory(lengthPos, 4 - lengthPos), cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0)
                    {
                        throw new SshException("Connection closed.");
                    }
                    lengthPos += bytesRead;
                }
                sshPacketSize = BinaryPrimitives.ReadUInt32BigEndian(lengthBuf.AsSpan(0));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(lengthBuf);
            }

            if (sshPacketSize > 35000)
            {
                throw new SshException("Invalid message sent, packet was too large!");
            }

            int bufferLength = (int)(4 + 4 + sshPacketSize + hmacSize);
            var buffer = ArrayPool<byte>.Shared.Rent(bufferLength);

            ByteWriter.WriteUint(buffer.AsSpan(0), packetSequenceNumber);
            ByteWriter.WriteUint(buffer.AsSpan(4), sshPacketSize);
            var bufferPosition = 8;

            // Read encrypted body + MAC.
            while (bufferPosition < bufferLength)
            {
                var bytesRead = await stream.ReadAsync(buffer.AsMemory(bufferPosition, bufferLength - bufferPosition), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    throw new SshException("Connection closed.");
                }
                bufferPosition += bytesRead;
            }

            return new SshPacket(buffer, 4, (int)(4 + sshPacketSize), pooled: true);
        }
    }
}
