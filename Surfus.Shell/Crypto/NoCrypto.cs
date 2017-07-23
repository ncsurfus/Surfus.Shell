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
        /// Stores extra data when reading the length of a packet.
        /// </summary>
        private byte[] _buffer = new byte[2048];

        private int _readPosition = 0;

        private int _writePosition = 0;

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
        internal override async Task<SshPacket> ReadPacketAsync(NetworkStream networkStream, CancellationToken cancellationToken)
        {
            var bufferFree = _buffer.Length - _writePosition;
            if (bufferFree < 4) // Check if there is enough room in the buffer to read or store an entire Length;
            {
                // Reset buffer to beginning.
                for (int i = _writePosition; i != bufferFree; i++)
                {
                    _buffer[i - _writePosition] = _buffer[_writePosition];
                }
                _readPosition = 0;
                _writePosition = bufferFree;
            }

            while (_writePosition - _readPosition < 4) // Read data until we have at least 4 bytes..
            {
                var bytesRead = await networkStream.ReadAsync(_buffer, _writePosition, _buffer.Length - _writePosition, cancellationToken);
                _writePosition += bytesRead;
            }

            var packetLength = ByteReader.ReadUInt32(_buffer, _readPosition) + 4; // Get size of packet + packet length integer
            if (packetLength > 35004) throw new InvalidOperationException($"Packet length is too large {packetLength}");

            // Check to see if we can fit the entire packet in our buffer. If so, read the entire packet into the buffer.
            if (_buffer.Length - _writePosition >= packetLength - (_writePosition - _readPosition))
            {
                while (_writePosition - _readPosition < packetLength) // Read until the data left to read 
                {
                    var bytesRead = await networkStream.ReadAsync(_buffer, _writePosition, _buffer.Length - _writePosition, cancellationToken);
                    _writePosition += bytesRead;
                }

                // Get the packet out of the buffer.
                // Our buffer is static and the contents *will* , so we *must* allocate a new buffer that includes the packet length.
                var fullPacket = new byte[packetLength];
                Array.Copy(_buffer, _readPosition, fullPacket, 0, _writePosition - _readPosition);
                _readPosition = _writePosition;
                return new SshPacket(fullPacket);
            }

            // The data is to big to be stored completely in the rest of our bufer
            // Get the first part of our packet out of the buffer.
            // Our buffer is static and the contents *will* , so we *must* allocate a new buffer that includes the packet length.
            var firstPacket = new byte[packetLength - _writePosition - _readPosition];
            Array.Copy(_buffer, _readPosition, firstPacket, 0, _writePosition - _readPosition);
            _readPosition = 0;
            _writePosition = 0;
            var secondPacket = await networkStream.ReadBytesAsync(packetLength - (uint)firstPacket.Length, cancellationToken);
            return new SshPacket(firstPacket, secondPacket);
        }

        /// <summary>
        /// Provides no encryption and returns the data back.
        /// </summary>
        /// <param name="plainText">The plaintext data.</param>
        /// <returns></returns>
        internal override byte[] Encrypt(byte[] plainText)
        {
            return plainText;
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
