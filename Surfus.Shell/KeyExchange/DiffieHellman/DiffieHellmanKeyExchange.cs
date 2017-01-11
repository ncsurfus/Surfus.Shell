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

        /// <summary>
        /// This method conducts the Diffie-Hellman Key Exchange with the remote party.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        /// <exception cref="SshException">
        /// Throws an SshException if the key exchange fails.
        /// </exception>
        public override async Task ExchangeAsync()
        {
            try
            {
				await _sshClient.Log("DiffieHellmanKeyExchange Selected");
                // Begin waiting for the 'Reply' Message.
                var replyMessageTask = GetReplyMessageAsync();

                // Send the 'Init' message to begin the Diffie-Hellman Key Exchange.
                await SendInitMessageAsync();

                // Receive the 'Reply' Message.
                var reply = await replyMessageTask;

                // Verify 'F' is in the range of [1, p-1]
                if (reply.F < 1 || reply.F > P - 1)
                {
					await _sshClient.Log("Invalid 'F' from server!");
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
						await _sshClient.Log("Invalid Host Signature.");
                        throw new SshException("Invalid Host Signature.");
                    }
                }
            }
            catch (Exception ex)
            {
				await _sshClient.Log("Key Exchange Failed: " + ex.ToString());
                await _sshClient.Disconnect(Disconnect.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, ex);
            }
        }

        /// <summary>
        /// Gets the 'reply' message from the server.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        /// <exception cref="SshException">
        /// Throws an SshException if the server not does respond with the appropriate message.
        /// </exception>
        public async Task<DhReply> GetReplyMessageAsync()
        {
            var replyMessageEvent = await GetDiffieHellmanMessageAsync();
            if (replyMessageEvent.Type != MessageType.SSH_MSG_KEX_Exchange_31)
            {
				await _sshClient.Log("The remote party sent an unexpected message during the key exchange. The Diffie-Hellman Key Exchange has failed.");
                throw new SshException(
                    "The remote party sent an unexpected message during the key exchange. The Diffie-Hellman Key Exchange has failed.");
            }

            return new DhReply(replyMessageEvent.Buffer);
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
        /// Sends the 'init' message to the server.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public Task SendInitMessageAsync()
        {
            return _sshClient.WriteMessage(new DhInit(E));
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

        /// <summary>
        /// Gets a message expected by the Diffie-Hellman Exchange.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        private async Task<MessageEvent> GetDiffieHellmanMessageAsync()
        {
            // If the message is not received within 1 minute, an exception will be thrown and the connection will be terminated.
            using (var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                return
                    await
                    _sshClient.GetMessageAsync(
                        m => m.Type == MessageType.SSH_MSG_KEX_Exchange_31, 
                        cancellationTokenSource.Token);
            }
        }
    }
}