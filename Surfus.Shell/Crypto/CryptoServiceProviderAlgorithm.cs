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
        /// Stores encrypted data when reading the length of a packet.
        /// </summary>
        private byte[] _encryptedData;

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

            int bufferSize = 2048;

            // Make buffer sizes even with input/output block sizes.
            _encryptedData = new byte[(bufferSize - (bufferSize % _decryptor.InputBlockSize))];
            _buffer = new byte[(bufferSize - (bufferSize % _decryptor.OutputBlockSize))];
        }

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
        internal override async Task<SshPacket> ReadPacketAsync(NetworkStream networkStream, CancellationToken cancellationToken)
        {
            var initialOutput = await ReadBlocks(networkStream, 1, cancellationToken).ConfigureAwait(false);
            var packetLength = ByteReader.ReadUInt32(initialOutput, 0);
            if (packetLength > 35000)
            {
                throw new InvalidOperationException("Packet length is too large");
            }

            if (packetLength + 4 <= initialOutput.Length)
            {
                return new SshPacket(new byte[4], initialOutput);
            }

            var totalEncryptedBlocks =
                (uint)((packetLength + 4) * (_decryptor.InputBlockSize / _decryptor.OutputBlockSize))
                / _decryptor.InputBlockSize;

            var secondaryOutput =
                await ReadBlocks(networkStream, (uint)(totalEncryptedBlocks - 1), cancellationToken).ConfigureAwait(false);

            return new SshPacket(new byte[4].Concat(initialOutput).ToArray(), secondaryOutput);
        }

        internal async Task<SshPacket> ReadPacketAsync2(NetworkStream networkStream, SshConnectionInfo connectionInfo, CancellationToken cancellationToken)
        {
            var bufferFree = _buffer.Length - _writePosition;
            if (_writePosition - _readPosition < _decryptor.InputBlockSize && bufferFree < _decryptor.InputBlockSize) // Check if there is enough room in the buffer to read or store an input packet;
            {
                // Reset buffer to beginning.
                for (int i = _writePosition; i != bufferFree; i++)
                {
                    _buffer[i - _writePosition] = _buffer[_writePosition];
                }
                _readPosition = 0;
                _writePosition = bufferFree;
            }

            while (_writePosition - _readPosition < _decryptor.InputBlockSize) // Read data until we have at least 4 bytes..
            {
                var bytesRead = await networkStream.ReadAsync(_buffer, _writePosition, _buffer.Length - _writePosition, cancellationToken);
                _writePosition += bytesRead;
            }

            if (_decryptor.InputBlockSize != _decryptor.OutputBlockSize) // Move this check to when the decyptor is constructed.
            {
                throw new NotSupportedException("InputBlockSize must not be smaller than the output block size!");
            }

            // Decrypt first packet so we can get the length
            _decryptor.TransformBlock(_buffer, _readPosition, _decryptor.InputBlockSize, _buffer, _readPosition);

            var unencryptedLength = ByteReader.ReadUInt32(_buffer, _readPosition) + 4; // Get size of packet + packet length integer
            var encryptedLength = (int)((unencryptedLength / _decryptor.OutputBlockSize) * _decryptor.InputBlockSize) - _decryptor.InputBlockSize;
            if (unencryptedLength > 35004) throw new InvalidOperationException($"Packet length is too large {unencryptedLength}");

            // Check to see if we can fit the entire packet in our buffer. If so, read the entire packet into the buffer.
            if (_buffer.Length - _writePosition >= encryptedLength - (_writePosition - _readPosition))
            {
                while (_writePosition - _readPosition < encryptedLength) // Read until the data left to read 
                {
                    var bytesRead = await networkStream.ReadAsync(_buffer, _writePosition, _buffer.Length - _writePosition, cancellationToken);
                    _writePosition += bytesRead;
                }

                // Get the packet out of the buffer.
                // The contents of _buffer *will* change, so we *must* allocate a new buffer that includes the packet length.
                var fullPacket = new byte[unencryptedLength];
                // Copy our first unencrypted packet and then decrypt the rest of the packet to our array.
                Array.Copy(_buffer, _readPosition, fullPacket, 0, _decryptor.OutputBlockSize);
                
                // If we had less data than we put in, let's adjust the reading position.
                _readPosition += _decryptor.InputBlockSize - _decryptor.OutputBlockSize;
                _decryptor.TransformBlock(_buffer, _readPosition, encryptedLength, fullPacket, _decryptor.OutputBlockSize);
                _readPosition += encryptedLength;

                // TODO: Need to verify MAC here!
                return new SshPacket(fullPacket);
            }

            // The data is to big to be stored completely in the rest of our buffer.
            // Create an array the size of the *encryptedLength* (which must be larger or equal to our unencrypted length!)
            // We will ignore anything extra later on.
            var bigPacket = new byte[encryptedLength];

            // Copy our first unencrypted packet
            Array.Copy(_buffer, _readPosition, bigPacket, 0, _decryptor.OutputBlockSize);
            var position = _decryptor.OutputBlockSize;

            if(_readPosition + _decryptor.InputBlockSize != _writePosition) // Check if there is more data in the buffer than just the first block.
            {
                // Let's decrypt it over to our new buffer.
                position += _decryptor.TransformBlock(_buffer, _readPosition + _decryptor.InputBlockSize, _writePosition - _readPosition - _decryptor.InputBlockSize, bigPacket, position);
            }

            var unencryptedPosition = position;
            while (position != unencryptedLength) // Copy the rest of our data into our new buffer (leave it encrypted)
            {
                var bytesRead = await networkStream.ReadAsync(bigPacket, position, bigPacket.Length - position, cancellationToken);
                position += bytesRead;
            }
           unencryptedPosition += _decryptor.TransformBlock(bigPacket, unencryptedPosition, position - unencryptedPosition, bigPacket, unencryptedPosition);
            
            // TODO: Need to verify MAC here!
            _readPosition = 0;
            _writePosition = 0;
            return new SshPacket(bigPacket);
        }

        /// <summary>
        /// Decrypts data from a network stream.
        /// </summary>
        /// <param name="networkStream">The network stream to read the encrypted data from.</param>
        /// <param name="blocks">blocks * blocksize determines how much data to read from the stream.</param>
        /// <param name="cancellationToken">The cancellation token associated with the async method.</param>
        /// <returns></returns>
        private async Task<byte[]> ReadBlocks(NetworkStream networkStream, uint blocks, CancellationToken cancellationToken)
        {
            var encryptedInput = await networkStream.ReadBytesAsync((uint)(_decryptor.InputBlockSize * blocks), cancellationToken).ConfigureAwait(false);
            var decryptedOutput = new byte[_decryptor.OutputBlockSize * blocks];
            var initialOutput = _decryptor.TransformBlock(
                encryptedInput, 
                0, 
                encryptedInput.Length, 
                decryptedOutput, 
                0);
            if (initialOutput != decryptedOutput.Length)
            {
                throw new Exception("Invalid Decryption");
            }

            return decryptedOutput;
        }

        
        /// <summary>
        /// Decrypts data from a network stream.
        /// </summary>
        /// <param name="networkStream">The network stream to read the encrypted data from.</param>
        /// <param name="cancellationToken">The cancellation token associated with the async method.</param>
        /// <returns></returns>
        private async Task<int> ReadEncryptedData(NetworkStream networkStream, byte[] buffer, int index, CancellationToken cancellationToken)
        {
            var spaceAvailable = ((buffer.Length - index) / _decryptor.OutputBlockSize) * _decryptor.InputBlockSize;
            if(spaceAvailable > _encryptedData.Length)
            {
                spaceAvailable = _encryptedData.Length;
            }
            Console.WriteLine(spaceAvailable);
            var encryptedBytesRead = await networkStream.ReadAsync(_encryptedData, 0, spaceAvailable);
            while(encryptedBytesRead % _decryptor.InputBlockSize != 0)
            {
                Console.Write("Test2 - " + _decryptor.InputBlockSize + " - "+ encryptedBytesRead + " - " + (spaceAvailable - encryptedBytesRead));
                encryptedBytesRead += await networkStream.ReadAsync(_encryptedData, encryptedBytesRead, spaceAvailable - encryptedBytesRead, cancellationToken);
                Console.WriteLine(" -  " + encryptedBytesRead);
            }
            Console.WriteLine("Escaped");
            return _decryptor.TransformBlock(_encryptedData, 0, encryptedBytesRead, buffer, index);
        }
    }
}