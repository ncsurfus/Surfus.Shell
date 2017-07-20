using System.Security.Cryptography;

namespace Surfus.Shell.Crypto
{
    /// <summary>
    /// Provides triple des crypto.
    /// </summary>
    internal sealed class TripleDesCryptoAlgorithm : CryptoServiceProviderAlgorithm
    {
        /// <summary>
        /// Creates a triple des CBC with zero padding.
        /// </summary>
        /// <returns></returns>
		private static TripleDES CreateTripleDesCbcZeroPadding()
		{
			var tripleDes = TripleDES.Create();
			tripleDes.Mode = CipherMode.CBC;
			tripleDes.Padding = PaddingMode.Zeros;
			return tripleDes;
		}

        /// <summary>
        /// Creates a triple DES algorithm.
        /// </summary>
		public TripleDesCryptoAlgorithm() : base (CreateTripleDesCbcZeroPadding())
        {
			
        }


        /// <summary>
        /// Gets the size of the cipher block.
        /// </summary>
        internal override int CipherBlockSize { get; } = 8;

        /// <summary>
        /// Gets the size of the Initialization Vector.
        /// </summary>
        internal override int InitializationVectorSize { get; } = 8;

        /// <summary>
        /// Gets the key size.
        /// </summary>
        internal override int KeySize { get; } = 24;
    }
}