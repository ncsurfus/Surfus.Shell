// --------------------------------------------------------------------------------------------------------------------
// <copyright file="KeyExchangeAlgorithm.cs" company="Nathan Surfus">
//   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
//   THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//   IN THE SOFTWARE.
// </copyright>
// <summary>
//   Provides the fundamentals, K and H, that all key exchanges must implement. This class also implements the creation
//   of the appropriate key exchange class from the ssh string.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using Surfus.Shell.KeyExchange.DiffieHellman;
using Surfus.Shell.KeyExchange.DiffieHellmanGroupExchange;

namespace Surfus.Shell.KeyExchange
{
    /// <summary>
    /// Serves as the base for all key exchange algorithms.
    /// </summary>
    internal abstract class KeyExchangeAlgorithm
    {
        /// <summary>
        /// Supported key exchange algorithms.
        /// </summary>
        public static string[] Supported
            =>
                new[]
                    {
                        "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1", 
                    };

        /// <summary>
        /// Gets the hash created from the key exchange algorithm.
        /// </summary>
        public byte[] H { get; protected set; }

        /// <summary>
        /// Gets the shared secret exchanged by the key exchange algorithm.
        /// </summary>
        public BigInteger K { get; protected set; }

        /// <summary>
        /// Creates the specified key exchange algorithm.
        /// </summary>
        /// <param name="client">
        /// The SshClient representing the ssh connection.
        /// </param>
        /// <param name="exchangeResult">
        /// The result of the KexInit exchange.
        /// </param>
        public static KeyExchangeAlgorithm Create(SshClient client, KexInitExchangeResult exchangeResult)
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
                    throw new SshException("Key Exchange Type Not Supported");
            }
        }

        /// <summary>
        /// Conducts the key exchange.
        /// </summary>
        public abstract Task ExchangeAsync();

        /// <summary>
        /// Generates the appropriate key used by each cipher.
        /// </summary>
        public byte[] GenerateKey(char letter, byte[] sessionId, int requiredBytes)
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
                SshClient.RandomGenerator.GetBytes(randomBytes);
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
    }
}