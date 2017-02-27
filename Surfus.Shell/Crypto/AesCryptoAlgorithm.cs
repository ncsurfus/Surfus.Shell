using System.Security.Cryptography;

namespace Surfus.Shell.Crypto
{
    internal sealed class AesCryptoAlgorithm : CryptoServiceProviderAlgorithm
    {
		private static Aes CreateAesCBCZeroPadding(int keySize, CipherMode cipherMode)
		{
			var aes = Aes.Create();
			aes.KeySize = keySize;
			aes.Mode = cipherMode;
			aes.Padding = PaddingMode.Zeros;
			return aes;
		}

		public AesCryptoAlgorithm(int keySizeBits, CipherMode cipherMode) : base (CreateAesCBCZeroPadding(keySizeBits, cipherMode))
        {
            KeySize = keySizeBits / 8;
        }

        public override int CipherBlockSize { get; } = 16;
        public override int InitializationVectorSize { get; } = 16;
        public override int KeySize { get; }
    }
}