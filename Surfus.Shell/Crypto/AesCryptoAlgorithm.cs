using System.Security.Cryptography;

namespace Surfus.Shell.Crypto
{
    public sealed class AesCryptoAlgorithm : CryptoServiceProviderAlgorithm
    {
        /// <summary>
        /// Creates an AES Crypto CBC algorithm with no padding. SSH packets are always block-aligned.
        /// </summary>
        /// <param name="keySize">The AES key size.</param>
        /// <param name="cipherMode">The AES cipher mode.</param>
        /// <returns></returns>
        private static Aes CreateAesCbc(int keySize, CipherMode cipherMode)
        {
            var aes = Aes.Create();
            aes.KeySize = keySize;
            aes.Mode = cipherMode;
            aes.Padding = PaddingMode.None;
            return aes;
        }

        /// <summary>
        /// Creates an AES crypto algorithm.
        /// </summary>
        /// <param name="keySizeBits">The AES key size.</param>
        /// <param name="cipherMode">The AES cipher mode.</param>
        internal AesCryptoAlgorithm(int keySizeBits, CipherMode cipherMode)
            : base(CreateAesCbc(keySizeBits, cipherMode))
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
