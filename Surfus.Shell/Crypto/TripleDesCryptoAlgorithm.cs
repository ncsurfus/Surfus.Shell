using System.Security.Cryptography;

namespace Surfus.Shell.Crypto
{
    internal sealed class TripleDesCryptoAlgorithm : CryptoServiceProviderAlgorithm
    {
		private static TripleDES CreateTripleDesCBCZeroPadding()
		{
			var tripleDes = TripleDES.Create();
			tripleDes.Mode = CipherMode.CBC;
			tripleDes.Padding = PaddingMode.Zeros;
			return tripleDes;
		}

		public TripleDesCryptoAlgorithm() : base (CreateTripleDesCBCZeroPadding())
        {
			
        }

        public override int CipherBlockSize { get; } = 8;
        public override int InitializationVectorSize { get; } = 8;
        public override int KeySize { get; } = 24;
    }
}