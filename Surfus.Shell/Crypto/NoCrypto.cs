using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.Crypto
{
    /// <summary>
    /// Represents no crypto algorithm.
    /// </summary>
    internal class NoCrypto : CryptoAlgorithm
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

        public override void Dispose()
        {
        }

        /// <summary>
        /// Reads a packet from the network stream.
        /// </summary>
        /// <param name="networkStream">The underlying TCP network stream.</param>
        /// <param name="cancellationToken">The cancellation token used to cancel the task.</param>
        /// <returns></returns>
        internal override async Task<SshPacket> ReadPacketAsync(NetworkStream networkStream, uint packetSequenceNumber, int hmacSize, CancellationToken cancellationToken)
        {
            var blockSize = 8; // This code was made assuming the decryption and encryption block sizes are the same!
            var expectedPacketSize = 768; // We're going to initialize the buffer to the average expected packet length. Unencrypted size will be higher due to BigIntegers in initial key exchange!
            var buffer = new byte[4 + blockSize + expectedPacketSize + hmacSize];// Array Length: uint (packetSequenceNumber) + uint (packet size) + expectedPacketSize + hmac size

            ByteWriter.WriteUint(buffer, 0, packetSequenceNumber); // Write first uint, which is the packet sequence number.
            var packetStart = 4; // This is where we actually start adding packet data, skipping the provided packet sequence number..
            var bufferPosition = 4; // Tracks where we last wrote data into our buffer.

            // Read enough data until we have at least 1 block.
            while (bufferPosition != blockSize + packetStart)
            {
                bufferPosition += await networkStream.ReadAsync(buffer, bufferPosition, blockSize + packetStart - bufferPosition, cancellationToken);
            }

            var sshPacketSize = ByteReader.ReadUInt32(buffer, 4); // Get the length of the packet.
            if (sshPacketSize > 35000) throw new SshException("Invalid message sent, packet was to large!");
            int bufferLength = (int)(4 + 4 + sshPacketSize + hmacSize); // Calculate the full size of what our buffer *should* be.

            if (buffer.Length < bufferLength) // Check to see if we need a bigger buffer and should allocate additional data.
            {
                Console.WriteLine("allocating?");
                Array.Resize(ref buffer, bufferLength);// Array Length: uint (packetSequenceNumber) + uint (packet size) + packet + hmac size
            }

            while (bufferPosition != bufferLength) // Read the rest of the data from the buffer. This loop may not even run if we've already read everything..
            {
                bufferPosition += await networkStream.ReadAsync(buffer, bufferPosition, bufferLength - bufferPosition, cancellationToken);
            }

            return new SshPacket(buffer, 4, bufferLength - 4 - hmacSize);
        }

        /// <summary>
        /// Provides no encryption and returns the data back.
        /// </summary>
        /// <param name="plainText">The plaintext data.</param>
        /// <returns></returns>
        internal override ArraySegment<byte> Encrypt(byte[] plainText, int offset, int length)
        {
            return new ArraySegment<byte>(plainText, offset, length);
        }

        /// <summary>
        /// Initializes the no-crypto algorithm by doing nothing.
        /// </summary>
        /// <param name="initializationVector">The initilization vector.</param>
        /// <param name="key">The key.</param>
        internal override void Initialize(byte[] initializationVector, byte[] key)
        {
            
        }
    }
}
