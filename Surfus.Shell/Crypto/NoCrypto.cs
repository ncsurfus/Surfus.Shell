using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Crypto
{
    /// <summary>
    /// Represents no crypto algorithm.
    /// </summary>
    public class NoCrypto : CryptoAlgorithm
    {
        /// <summary>
        /// The minimum cipher block size specified by SSH.
        /// </summary>
        internal override int CipherBlockSize { get; } = 8;

        /// <summary>
        /// A zero initilization vector (there is none).
        /// </summary>
        internal override int InitializationVectorSize { get; } = 0;

        /// <summary>
        /// A zero key size (there is none).
        /// </summary>
        internal override int KeySize { get; } = 0;

        public override void Dispose() { }

        /// <summary>
        /// Reads a packet from the transport stream.
        /// </summary>
        /// <param name="stream">The underlying transport stream.</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the task.</param>
        /// <returns></returns>
        internal override async Task<SshPacket> ReadPacketAsync(
            Stream stream,
            uint packetSequenceNumber,
            int hmacSize,
            bool isEtm,
            CancellationToken cancellationToken
        )
        {
            var blockSize = CipherBlockSize;

            // Read the first block to get the packet length.
            var firstBlock = ArrayPool<byte>.Shared.Rent(blockSize);
            uint sshPacketSize;
            try
            {
                var pos = 0;
                while (pos < blockSize)
                {
                    var bytesRead = await stream.ReadAsync(firstBlock.AsMemory(pos, blockSize - pos), cancellationToken);
                    if (bytesRead == 0)
                    {
                        throw new SshException("Connection closed.");
                    }
                    pos += bytesRead;
                }
                sshPacketSize = ByteReader.ReadUInt32(firstBlock.AsSpan(0));

                if (sshPacketSize > 35000)
                {
                    throw new SshException("Invalid message sent, packet was too large!");
                }

                int bufferLength = (int)(4 + 4 + sshPacketSize + hmacSize);
                var buffer = ArrayPool<byte>.Shared.Rent(bufferLength);

                ByteWriter.WriteUint(buffer.AsSpan(0), packetSequenceNumber);
                // Copy the full first block (length + start of body) into the buffer.
                firstBlock.AsSpan(0, blockSize).CopyTo(buffer.AsSpan(4));
                var bufferPosition = 4 + blockSize;

                // Read the rest of the packet.
                while (bufferPosition < bufferLength)
                {
                    var bytesRead = await stream.ReadAsync(buffer.AsMemory(bufferPosition, bufferLength - bufferPosition), cancellationToken);
                    if (bytesRead == 0)
                    {
                        throw new SshException("Connection closed.");
                    }
                    bufferPosition += bytesRead;
                }

                return new SshPacket(buffer, 4, bufferLength - 4 - hmacSize, pooled: true);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(firstBlock);
            }
        }

        /// <summary>
        /// Provides no encryption and returns the data back.
        /// </summary>
        /// <param name="plainText">The plaintext data.</param>
        /// <returns></returns>
        internal override void Encrypt(byte[] plainText, int offset, int length)
        {
            return;
        }

        internal override void Decrypt(byte[] cipherText, int offset, int length)
        {
            return;
        }

        /// <summary>
        /// Initializes the no-crypto algorithm by doing nothing.
        /// </summary>
        /// <param name="initializationVector">The initilization vector.</param>
        /// <param name="key">The key.</param>
        internal override void Initialize(byte[] initializationVector, byte[] key) { }
    }
}
