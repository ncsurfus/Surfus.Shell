﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
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
        internal static string[] Supported
            =>
                new[]
                    {
                        "diffie-hellman-group-exchange-sha1", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"
                    };

        /// <summary>
        /// Gets the hash created from the key exchange algorithm.
        /// </summary>
        internal byte[] H { get; set; }

        /// <summary>
        /// Gets the shared secret exchanged by the key exchange algorithm.
        /// </summary>
        internal BigInt K { get; set; }

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

        /// <summary>
        /// Conducts the key exchange.
        /// </summary>
        internal abstract Task InitiateKeyExchangeAlgorithmAsync(CancellationToken cancellationToken);

        /// <summary>
        /// Generates the appropriate key used by each cipher.
        /// </summary>
        internal byte[] GenerateKey(char letter, byte[] sessionId, int requiredBytes)
        {
            if (letter != 'A' && letter != 'B' && letter != 'C' && letter != 'D' && letter != 'E' && letter != 'F')
            {
                throw new ArgumentException(nameof(letter));
            }

            var hashList = new List<byte[]>();

            using (var hashAlgorithm = CreateHashAlgorithm())
            {
                using (var memoryStream = new MemoryStream())
                {
                    memoryStream.WriteBigInteger(K);
                    memoryStream.Write(H);
                    memoryStream.WriteByte(Encoding.UTF8.GetBytes(new[] { letter })[0]);
                    memoryStream.Write(sessionId);
                    hashList.Add(hashAlgorithm.ComputeHash(memoryStream.ToArray()));
                }

                while (hashList.Sum(x => x.Length) < requiredBytes)
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        memoryStream.WriteBigInteger(K);
                        memoryStream.Write(H);
                        foreach (var hashEntry in hashList)
                        {
                            memoryStream.Write(hashEntry);
                        }

                        hashList.Add(hashAlgorithm.ComputeHash(memoryStream.ToArray()));
                    }
                }
            }

            return hashList.SelectMany(x => x).ToArray();
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
            }
            while (randomValue < minValue || randomValue > maxValue);
            return randomValue;
        }

        /// <summary>
        /// Supported key exchanges.
        /// </summary>
        protected abstract HashAlgorithm CreateHashAlgorithm();

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal abstract Task<bool> ProcessMessage30Async(MessageEvent message, CancellationToken cancellationToken);

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal abstract Task<bool> ProcessMessage31Async(MessageEvent message, CancellationToken cancellationToken);

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal abstract Task<bool> ProcessMessage32Async(MessageEvent message, CancellationToken cancellationToken);

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal abstract Task<bool> ProcessMessage33Async(MessageEvent message, CancellationToken cancellationToken);

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal abstract Task<bool> ProcessMessage34Async(MessageEvent message, CancellationToken cancellationToken);
    }
}