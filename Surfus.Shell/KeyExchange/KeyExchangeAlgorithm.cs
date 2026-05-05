using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.KeyExchange.DiffieHellman;
using Surfus.Shell.KeyExchange.DiffieHellmanGroupExchange;
using Surfus.Shell.Messages;

namespace Surfus.Shell.KeyExchange
{
    /// <summary>
    /// Serves as the base for all key exchange algorithms.
    /// </summary>
    public abstract class KeyExchangeAlgorithm
    {
        private static readonly RandomNumberGenerator RandomGenerator = RandomNumberGenerator.Create();
        public abstract Task<KeyExchangeResult> ExchangeAsync(CancellationToken cancellationToken);

        protected static bool KexThrowIfNotMessageType(MessageEvent messageEvent, MessageType expectedMessageType)
        {
            if (messageEvent.Type == expectedMessageType)
            {
                return true;
            }
            return messageEvent.Type switch
            {
                MessageType.SSH_MSG_KEX_Exchange_30
                or MessageType.SSH_MSG_KEX_Exchange_31
                or MessageType.SSH_MSG_KEX_Exchange_32
                or MessageType.SSH_MSG_KEX_Exchange_33
                or MessageType.SSH_MSG_KEX_Exchange_34 => throw new NotImplementedException(),
                _ => false,
            };
        }

        /// <summary>
        /// Generates the appropriate key used by each cipher.
        /// </summary>
        internal byte[] GenerateKey(Memory<byte> h, BigInt k, char letter, Memory<byte> sessionId, int requiredBytes)
        {
            if (letter != 'A' && letter != 'B' && letter != 'C' && letter != 'D' && letter != 'E' && letter != 'F')
            {
                throw new ArgumentException(null, nameof(letter));
            }

            using (var hashAlgorithm = CreateHashAlgorithm())
            {
                var keySize = hashAlgorithm.HashSize / 8;

                while (keySize < requiredBytes)
                {
                    keySize += hashAlgorithm.HashSize / 8;
                }

                var keyWriter = new ByteWriter(keySize);

                var firstHashWriter = new ByteWriter(k.GetBigIntegerSize() + h.GetByteBlobSize() + 1 + sessionId.GetByteBlobSize());
                firstHashWriter.WriteBigInteger(k);
                firstHashWriter.WriteByteBlob(h);
                firstHashWriter.WriteByte((byte)letter);
                firstHashWriter.WriteByteBlob(sessionId);
                keyWriter.WriteByteBlob(hashAlgorithm.ComputeHash(firstHashWriter.Bytes));

                while (keyWriter.Position < requiredBytes)
                {
                    var repeatHashWriter = new ByteWriter(k.GetBigIntegerSize() + h.GetByteBlobSize() + keyWriter.Position);
                    repeatHashWriter.WriteBigInteger(k);
                    repeatHashWriter.WriteByteBlob(h);
                    repeatHashWriter.WriteByteBlob(keyWriter.Bytes.AsMemory(0, keyWriter.Position));
                    keyWriter.WriteByteBlob(hashAlgorithm.ComputeHash(repeatHashWriter.Bytes));
                }

                return keyWriter.Bytes;
            }
        }

        /// <summary>
        /// Generates a random big integer between two values.
        /// </summary>
        protected static BigInteger GenerateRandomBigInteger(BigInteger minValue, BigInteger maxValue)
        {
            BigInteger randomValue;
            var randomBytes = new byte[maxValue.ToByteArray().Length + 1];
            do
            {
                RandomGenerator.GetBytes(randomBytes);
                randomBytes[randomBytes.Length - 1] = 0;
                randomValue = new BigInteger(randomBytes);
            } while (randomValue < minValue || randomValue > maxValue);
            return randomValue;
        }

        /// <summary>
        /// Supported key exchanges.
        /// </summary>
        protected abstract HashAlgorithm CreateHashAlgorithm();
    }
}
