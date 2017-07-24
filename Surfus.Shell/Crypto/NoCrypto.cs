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
            // This code was made assuming the decryption and encryption block sizes are the same!
            var blockSize = CipherBlockSize;
            var _buffer = new byte[4 + blockSize];
            ByteWriter.WriteUint(_buffer, 0, packetSequenceNumber); // Write first uint (packet sequence number)
            var _bufferPosition = 4;

            // Read enough data until we have at least 1 block.
            while (_bufferPosition != _buffer.Length)
            {           
                _bufferPosition += await networkStream.ReadAsync(_buffer, _bufferPosition, _buffer.Length - _bufferPosition, cancellationToken);
            }
            
            var packetSize = ByteReader.ReadUInt32(_buffer, 4); // Get packet size...
            if (packetSize > 35000) throw new SshException("Invalid message sent, packet was to large!");
            Array.Resize(ref _buffer, (int)(4 + 4 + packetSize + hmacSize));// Array Length: uint (packetSequenceNumber) + uint (packet size) + packet + hmac size

            while (_bufferPosition != _buffer.Length) // Read the rest of the data from the buffer. This loop may not even run if we've already read everything..
            {
                _bufferPosition += await networkStream.ReadAsync(_buffer, _bufferPosition, _buffer.Length - _bufferPosition, cancellationToken);
            }
            return new SshPacket(_buffer, 4, _buffer.Length - 4 - hmacSize);
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
