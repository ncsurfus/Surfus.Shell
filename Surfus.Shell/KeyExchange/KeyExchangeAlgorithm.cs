using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using System.Threading;
using Surfus.Shell.KeyExchange.DiffieHellmanGroupExchange;
using Surfus.Shell.KeyExchange.DiffieHellman;

namespace Surfus.Shell.KeyExchange
{
    /// <summary>
    /// Serves as the base for all key exchange algorithms.
    /// </summary>
    internal abstract class KeyExchangeAlgorithm
    {
        private static readonly RandomNumberGenerator RandomGenerator = RandomNumberGenerator.Create();

        /// <summary>
        /// Supported key exchange algorithms.
        /// </summary>
        internal static string[] Supported =>
            new[]
            {
                "diffie-hellman-group-exchange-sha256",
                "diffie-hellman-group14-sha256",
                "diffie-hellman-group16-sha512",
                "diffie-hellman-group18-sha512",
                "diffie-hellman-group-exchange-sha1",
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group1-sha1",
            };

        /// <summary>
        /// Creates the specified key exchange algorithm.
        /// </summary>
        /// <param name="client">
        /// The SshClient representing the ssh connection.
        /// </param>
        /// <param name="exchangeResult">
        /// The result of the KexInit exchange.
        /// </param>
        internal static KeyExchangeAlgorithm Create(SshClient client, KexInitExchangeResult exchangeResult)
        {
            switch (exchangeResult.KeyExchangeAlgorithm)
            {
                case "diffie-hellman-group18-sha512":
                    return new DiffieHellmanGroup18Sha512(client, exchangeResult);
                case "diffie-hellman-group16-sha512":
                    return new DiffieHellmanGroup16Sha512(client, exchangeResult);
                case "diffie-hellman-group14-sha256":
                    return new DiffieHellmanGroup14Sha256(client, exchangeResult);
                case "diffie-hellman-group-exchange-sha256":
                    return new DiffieHellmanGroupKeyExchange(client, exchangeResult, "SHA256");
                case "diffie-hellman-group-exchange-sha1":
                    return new DiffieHellmanGroupKeyExchange(client, exchangeResult, "SHA1");
                case "diffie-hellman-group14-sha1":
                    return new DiffieHellmanGroup14Sha1(client, exchangeResult);
                case "diffie-hellman-group1-sha1":
                    return new DiffieHellmanGroup1Sha1(client, exchangeResult);
                default:
                    throw new SshException($"Key Exchange type {exchangeResult.KeyExchangeAlgorithm} is not supported");
            }
        }

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
                or MessageType.SSH_MSG_KEX_Exchange_34
                    => throw new NotImplementedException(),
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
                    repeatHashWriter.WriteByteBlob(keyWriter.Bytes, 0, keyWriter.Position);
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
