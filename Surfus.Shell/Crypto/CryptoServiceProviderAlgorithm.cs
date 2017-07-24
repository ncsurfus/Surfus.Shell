using System;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Crypto
{
    /// <summary>
    /// Implements a common core of methods for crypto algorithms.
    /// </summary>
    internal abstract class CryptoServiceProviderAlgorithm : CryptoAlgorithm
    {
        /// <summary>
        /// Stores extra data when reading the length of a packet.
        /// </summary>
        private byte[] _buffer;

        /// <summary>
        /// Tracks the read position.
        /// </summary>
        private int _readPosition = 0;

        /// <summary>
        /// Tracks the write position.
        /// </summary>
        private int _writePosition = 0;

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
        internal override async Task<SshPacket> ReadPacketAsync(NetworkStream networkStream, int macSize, CancellationToken cancellationToken)
        {
            // This code was made assuming the decryption and encryption block sizes are the same!
            var blockSize = _decryptor.InputBlockSize;

            if (_buffer.Length - _readPosition < blockSize) // Check to see if there is a block left to read within the buffer.
            {
                // Shift buffer left.
                var shiftStart = _readPosition; // Where to start copying the data.
                var shiftLength = _writePosition - _readPosition; // How much data we should copy.
                Array.Copy(_buffer, shiftStart, _buffer, 0, shiftLength); // Copying of data
                _readPosition = 0; // Reseting of values...
                _writePosition = shiftLength;
            }

            // Read enough data until we have at least 1 block.
            while (_writePosition - _readPosition < blockSize)
            {
                // Read as much data as possible into the buffer.
                _writePosition += await networkStream.ReadAsync(_buffer, _writePosition, _buffer.Length - _writePosition, cancellationToken);
            }

            _decryptor.TransformBlock(_buffer, _readPosition, blockSize, _buffer, _readPosition); // Decrypt the first block in the buffer.

            var sshPacketSize = ByteReader.ReadUInt32(_buffer, _readPosition); // Get packet size...
            var sshPacket = new byte[4 + 4 + sshPacketSize + macSize]; // Array Length: uint (packetSequenceNumber) + uint (packet size) + packet + hmac size
            var sshPacketPosition = 4; // Skip first uint - packet sequence number.
            var bufferedData = Math.Min(sshPacket.Length - sshPacketPosition, _writePosition - _readPosition); // The amount of data to copy over from the buffer.
            Array.Copy(_buffer, _readPosition, sshPacket, sshPacketPosition, bufferedData); // Copy data from buffer to sshPacket.
            _readPosition += bufferedData;
            sshPacketPosition += bufferedData;

            while (sshPacketPosition != sshPacket.Length) // Read the rest of the data from the buffer. This loop may not even run if we've already read everything..
            {
                sshPacketPosition += await networkStream.ReadAsync(sshPacket, sshPacketPosition, sshPacket.Length - sshPacketPosition, cancellationToken);
            }

            if(sshPacketSize > blockSize) // Check if this was more than a single block..
            {
                // Decrypt everything except the first block as that was already decrypted!
                _decryptor.TransformBlock(sshPacket, 4 + blockSize, sshPacket.Length - 4 - blockSize - macSize, sshPacket, 4 + blockSize);
            }
           
            if (_readPosition == _writePosition)
            {
                _readPosition = 0;
                _writePosition = 0;
            }

            return new SshPacket(sshPacket, true, macSize);
        }
    }
}