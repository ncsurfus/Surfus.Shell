using System.Security.Cryptography;
using Surfus.Shell.Crypto.AesCtr;

namespace Surfus.Shell.Crypto
{
    internal sealed class AesCtrCryptoAlgorithm : CryptoServiceProviderAlgorithm
    {
        /// <summary>
        /// Creates an AES CTR crypto algorithm.
        /// </summary>
        /// <param name="keySize">The AES key size.</param>
        /// <returns></returns>
		private static SymmetricAlgorithm CreateAesCtr(int keySize)
		{
			var aes = new AesCtrMode(keySize);
			return aes;
		}

        /// <summary>
        /// Creates an AES CTR crypto algorhtm. 
        /// </summary>
        /// <param name="keySizeBits">The AES key size in bits.</param>
		internal AesCtrCryptoAlgorithm(int keySizeBits) : base (CreateAesCtr(keySizeBits))
        {
            KeySize = keySizeBits / 8;
        }

        /// <summary>
        /// Gets the size of the cipher block.
        /// </summary>
        internal override int CipherBlockSize { get; } = 16;

        /// <summary>
        /// Gets the size of the Initialization Vector.
        /// </summary>
        internal override int InitializationVectorSize { get; } = 16;

        /// <summary>
        /// Gets the key size.
        /// </summary>
        internal override int KeySize { get; }
    }
}