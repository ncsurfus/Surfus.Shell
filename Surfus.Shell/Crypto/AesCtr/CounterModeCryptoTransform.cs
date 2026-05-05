// Credit to hanswolff https://gist.github.com/hanswolff/8809275

using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Crypto.AesCtr
{
    public class CounterModeCryptoTransform : ICryptoTransform
    {
        private readonly byte[] _counter;
        private readonly ICryptoTransform _counterEncryptor;
        private readonly SymmetricAlgorithm _symmetricAlgorithm;
        private readonly byte[] _xorMask;
        private int _xorMaskIndex;

        internal CounterModeCryptoTransform(SymmetricAlgorithm symmetricAlgorithm, byte[] key, byte[] counter)
        {
            if (symmetricAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(symmetricAlgorithm));
            }
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (counter == null)
            {
                throw new ArgumentNullException(nameof(counter));
            }
            if (counter.Length != symmetricAlgorithm.BlockSize / 8)
            {
                throw new ArgumentException(
                    String.Format(
                        "Counter size must be same as block size (actual: {0}, expected: {1})",
                        counter.Length,
                        symmetricAlgorithm.BlockSize / 8
                    )
                );
            }

            _symmetricAlgorithm = symmetricAlgorithm;
            _counter = counter;
            _xorMask = new byte[symmetricAlgorithm.BlockSize / 8];
            _xorMaskIndex = _xorMask.Length; // Force generation on first use

            var zeroIv = new byte[_symmetricAlgorithm.BlockSize / 8];
            _counterEncryptor = symmetricAlgorithm.CreateEncryptor(key, zeroIv);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var output = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            for (var i = 0; i < inputCount; i++)
            {
                if (_xorMaskIndex >= _xorMask.Length)
                    EncryptCounterThenIncrement();

                outputBuffer[outputOffset + i] = (byte)(inputBuffer[inputOffset + i] ^ _xorMask[_xorMaskIndex++]);
            }

            return inputCount;
        }

        private void EncryptCounterThenIncrement()
        {
            _counterEncryptor.TransformBlock(_counter, 0, _counter.Length, _xorMask, 0);
            _xorMaskIndex = 0;
            IncrementCounter();
        }

        private void IncrementCounter()
        {
            for (var i = _counter.Length - 1; i >= 0; i--)
            {
                if (++_counter[i] != 0)
                    break;
            }
        }

        public int InputBlockSize => _symmetricAlgorithm.BlockSize / 8;
        public int OutputBlockSize => _symmetricAlgorithm.BlockSize / 8;
        public bool CanTransformMultipleBlocks => true;
        public bool CanReuseTransform => false;

        public void Dispose() { _counterEncryptor?.Dispose(); }
    }
}
