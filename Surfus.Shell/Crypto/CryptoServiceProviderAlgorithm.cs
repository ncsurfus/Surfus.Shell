// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CryptoServiceProviderAlgorithm.cs" company="Nathan Surfus">
//   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
//   THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//   IN THE SOFTWARE.
// </copyright>
// <summary>
//  Implements a common core of methods for crypto algorithms.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

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
        public override byte[] Encrypt(byte[] byteArray)
        {
            var encryptedBlocks =
                new byte[byteArray.Length / _encryptor.InputBlockSize * _encryptor.OutputBlockSize];
            var totalEncryptedBytes = _encryptor.TransformBlock(byteArray, 0, byteArray.Length, encryptedBlocks, 0);
            if (totalEncryptedBytes != encryptedBlocks.Length)
            {
                throw new Exception("Invalid byteArray encryption");
            }

            return encryptedBlocks;
        }

        /// <summary>
        /// Initializes the cipher. You must initialize the cipher before caling Encrypt or ReadPacket.
        /// </summary>
        /// <param name="initializationVector">The initialization vector for the cipher.</param>
        /// <param name="key">The key for the cipher.</param>
        public override void Initialize(byte[] initializationVector, byte[] key)
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
        public override async Task<SshPacket> ReadPacketAsync(
            NetworkStream networkStream, 
            CancellationToken cancellationToken)
        {
            var initialOutput = await ReadBlocks(networkStream, 1, cancellationToken);
            var packetLength = initialOutput.FromBigEndianToUint();
            if (packetLength > 35000)
            {
                throw new InvalidOperationException("Packet length is too large");
            }

            if (packetLength + 4 <= initialOutput.Length)
            {
                return new SshPacket(initialOutput, new byte[] { });
            }

            var totalEncryptedBlocks =
                (uint)((packetLength + 4) * (_decryptor.InputBlockSize / _decryptor.OutputBlockSize))
                / _decryptor.InputBlockSize;

            var secondaryOutput =
                await ReadBlocks(networkStream, (uint)(totalEncryptedBlocks - 1), cancellationToken);

            return new SshPacket(initialOutput, secondaryOutput);
        }

        /// <summary>
        /// Decrypts data from a network stream.
        /// </summary>
        /// <param name="networkStream">The network stream to read the encrypted data from.</param>
        /// <param name="blocks">blocks * blocksize determines how much data to read from the stream.</param>
        /// <param name="cancellationToken">The cancellation token associated with the async method.</param>
        /// <returns></returns>
        private async Task<byte[]> ReadBlocks(
            NetworkStream networkStream, 
            uint blocks, 
            CancellationToken cancellationToken)
        {
            var encryptedInput =
                await networkStream.ReadBytesAsync((uint)(_decryptor.InputBlockSize * blocks), cancellationToken);
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
    }
}