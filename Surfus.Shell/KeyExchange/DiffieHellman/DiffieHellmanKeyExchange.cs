// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DiffieHellmanKeyExchange.cs" company="Nathan Surfus">
//   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
//   THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//   IN THE SOFTWARE.
// </copyright>
// <summary>
//   Implements the Diffie-Hellman Exchange.
//   RFC: https://tools.ietf.org/html/rfc4253
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.KeyExchange.DiffieHellman;
using Surfus.Shell.Signing;

namespace Surfus.Shell.KeyExchange.DiffieHellman
{
    /// <summary>
    /// Implements the Diffie-Hellman Exchange.
    /// </summary>
    internal abstract class DiffieHellmanKeyExchange : KeyExchangeAlgorithm
    {
        /// <summary>
        /// The result of the KexInit exchange.
        /// </summary>
        private readonly KexInitExchangeResult _kexInitExchangeResult;

        /// <summary>
        /// The SshClient representing the SSH connection.
        /// </summary>
        private readonly SshClient _sshClient;

        /// <summary>
        /// The signing algorithm.
        /// </summary>
        private Signer _signingAlgorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="DiffieHellmanKeyExchange"/> class.
        /// </summary>
        /// <param name="sshClient">
        /// The SSH client.
        /// </param>
        /// <param name="kexInitExchangeResult">
        /// The result of the KexInit exchange.
        /// </param>
        protected DiffieHellmanKeyExchange(SshClient sshClient, KexInitExchangeResult kexInitExchangeResult)
        {
            _sshClient = sshClient;
            _kexInitExchangeResult = kexInitExchangeResult;
        }

        /// <summary>
        /// E = g^x mod p
        /// </summary>
        protected abstract BigInteger E { get; }

        /// <summary>
        /// Gets the generator for the subgroup.
        /// </summary>
        protected virtual BigInteger G { get; } = new BigInteger(new byte[] { 2 });

        /// <summary>
        /// A large predefined safe prime number.
        /// </summary>
        protected abstract BigInteger P { get; }

        /// <summary>
        /// A random number between [1, q]
        /// </summary>
        protected abstract BigInteger X { get; }

        // Message Sources
        internal TaskCompletionSource<DhReply> DhReplyMessage = new TaskCompletionSource<DhReply>();

        /// <summary>
        /// This method conducts the Diffie-Hellman Key Exchange with the remote party.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        /// <exception cref="SshException">
        /// Throws an SshException if the key exchange fails.
        /// </exception>
        public override async Task ExchangeAsync(CancellationToken cancellationToken)
        {
            // Send the 'Init' message to begin the Diffie-Hellman Key Exchange.
            await SshClientStaticThread.WriteMessageAsync(_sshClient, new DhInit(E), cancellationToken);

            // Receive the 'Reply' Message.
            var reply = await DhReplyMessage.Task;

            // Verify 'F' is in the range of [1, p-1]
            if (reply.F < 1 || reply.F > P - 1)
            {
                throw new SshException("Invalid 'F' from server!");
            }

            // Generate the shared secret 'K'
            K = BigInteger.ModPow(reply.F, X, P);

            // Prepare the signing algorithm from the servers public key.
            _signingAlgorithm = Signer.CreateSigner(
                _kexInitExchangeResult.ServerHostKeyAlgorithm,
                reply.ServerPublicHostKeyAndCertificates);

            // Generate 'H', the computed hash. If data has been tampered via man-in-the-middle-attack 'H' will be incorrect and the connection will be terminated.
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteString(_sshClient.ConnectionInfo.ClientVersion);
                memoryStream.WriteString(_sshClient.ConnectionInfo.ServerVersion);
                memoryStream.WriteBinaryString(_kexInitExchangeResult.Client.GetBytes());
                memoryStream.WriteBinaryString(_kexInitExchangeResult.Server.GetBytes());
                memoryStream.WriteBinaryString(reply.ServerPublicHostKeyAndCertificates);
                memoryStream.WriteBigInteger(E);
                memoryStream.WriteBigInteger(reply.F);
                memoryStream.WriteBigInteger(K);

                H = Hash(memoryStream.ToArray());

                // Use the signing algorithm to verify the data sent by the server is correct.
                if (!_signingAlgorithm.VerifySignature(H, reply.HSignature))
                {
                    throw new SshException("Invalid Host Signature.");
                }
            }
        }

        /// <summary>
        /// Hashes the data with the hash algorithm specified in the constructor.
        /// </summary>
        /// <param name="data">
        /// The data to hash.
        /// </param>
        /// <returns>
        /// A byte array containing the hash.
        /// </returns>
        public byte[] Hash(byte[] data)
        {
            using (var shaGenerator = CreateHashAlgorithm())
            {
                return shaGenerator.ComputeHash(data);
            }
        }

        /// <summary>
        /// Creates the appropriate hashing algorithm.
        /// </summary>
        /// <returns>
        /// The <see cref="HashAlgorithm"/>.
        /// </returns>
        /// <exception cref="SshException">
        /// Throws if an unsupported SHA algorithm is specified.
        /// </exception>
        protected override HashAlgorithm CreateHashAlgorithm()
        {
            return SHA1.Create();
        }

        public override void SendKeyExchangeMessage30(MessageEvent message)
        {
            throw new NotImplementedException();
        }

        public override void SendKeyExchangeMessage31(MessageEvent message)
        {
            DhReplyMessage.TrySetResult(new DhReply(message.Buffer));
        }

        public override void SendKeyExchangeMessage32(MessageEvent message)
        {
            throw new NotImplementedException();
        }

        public override void SendKeyExchangeMessage33(MessageEvent message)
        {
            throw new NotImplementedException();
        }

        public override void SendKeyExchangeMessage34(MessageEvent message)
        {
            throw new NotImplementedException();
        }
    }
}