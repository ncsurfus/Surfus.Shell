using System.Security.Cryptography;
using Surfus.SecureShellCore.Crypto.AesCtr;

namespace Surfus.Shell.Crypto
{
    internal sealed class AesCtrCryptoAlgorithm : CryptoServiceProviderAlgorithm
    {
		private static SymmetricAlgorithm CreateAesCtr(int keySize)
		{
			var aes = new AesCtrMode(keySize);
			return aes;
		}

		public AesCtrCryptoAlgorithm(int keySizeBits) : base (CreateAesCtr(keySizeBits))
        {
            KeySize = keySizeBits / 8;
        }

        public override int CipherBlockSize { get; } = 16;
        public override int InitializationVectorSize { get; } = 16;
        public override int KeySize { get; }
    }
}