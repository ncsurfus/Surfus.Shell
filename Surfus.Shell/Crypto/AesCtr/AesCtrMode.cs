// Credit to hanswolff https://gist.github.com/hanswolff/8809275

using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Crypto.AesCtr
{
	public class AesCtrMode : SymmetricAlgorithm
	{
		private readonly Aes _aes;

		public AesCtrMode(int keySize)
		{
			_aes = Aes.Create();
			_aes.KeySize = keySize;
			_aes.Mode = CipherMode.ECB;
			_aes.Padding = PaddingMode.None;
		}

		public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] counter)
		{
			if (counter == null)
			{
				throw new ArgumentNullException(nameof(counter));
			}
			if (counter.Length != 16)
			{
				throw new ArgumentException(String.Format("Counter size must be same as block size (actual: {0}, expected: {1})",
				counter.Length, 16));
			}
			
			return new CounterModeCryptoTransform(_aes, rgbKey, counter);
		}

		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] counter)
		{
			if (counter == null)
			{
				throw new ArgumentNullException(nameof(counter));
			}
			if (counter.Length != 16)
			{
				throw new ArgumentException(String.Format("Counter size must be same as block size (actual: {0}, expected: {1})",
				counter.Length, 16));
			}

			return new CounterModeCryptoTransform(_aes, rgbKey, counter);
		}

		public override void GenerateKey()
		{
			_aes.GenerateKey();
		}

		public override void GenerateIV()
		{
			// IV not needed in Counter Mode
		}
	}
}
