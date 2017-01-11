// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DiffieHellmanGroupKeyExchange.cs" company="Nathan Surfus">
//   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
//   THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//   IN THE SOFTWARE.
// </copyright>
// <summary>
//   Implements the Diffie-Hellman Group Exchange.
//   RFC: https://www.ietf.org/rfc/rfc4419.txt
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
using Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup;
using Surfus.Shell.Signing;

namespace Surfus.Shell.KeyExchange.DiffieHellmanGroupExchange
{
    /// <summary>
    /// Implements the Diffie-Hellman Group Exchange.
    /// </summary>
    internal class DiffieHellmanGroupKeyExchange : KeyExchangeAlgorithm
    {
        /// <summary>
        /// The maximum group size.
        /// </summary>
        private const uint MaximumGroupSize = 8192;

        /// <summary>
        /// The minimum group size.
        /// </summary>
        private const uint MinimumGroupSize = 1024;

        /// <summary>
        /// The preferred group size.
        /// </summary>
        private const uint PreferredGroupSize = 2048;

        /// <summary>
        /// The result of the KexInit exchange.
        /// </summary>
        private readonly KexInitExchangeResult _kexInitExchangeResult;

        /// <summary>
        /// SHA version. Can be 'SHA1' or 'SHA256'.
        /// </summary>
        private readonly string _shaVersion;

        /// <summary>
        /// The SshClient representing the SSH connection.
        /// </summary>
        private readonly SshClient _sshClient;

        /// <summary>
        /// The signing algorithm.
        /// </summary>
        private Signer _signingAlgorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="DiffieHellmanGroupKeyExchange"/> class.
        /// </summary>
        /// <param name="sshClient">
        /// The SSH client.
        /// </param>
        /// <param name="kexInitExchangeResult">
        /// The result of the KexInit exchange.
        /// </param>
        /// <param name="shaVersion">
        /// The SHA version. Can be 'SHA1' or 'SHA256'.
        /// </param>
        public DiffieHellmanGroupKeyExchange(SshClient sshClient, KexInitExchangeResult kexInitExchangeResult, string shaVersion)
        {
            _sshClient = sshClient;
            _kexInitExchangeResult = kexInitExchangeResult;
            _shaVersion = shaVersion;
        }

        /// <summary>
        /// This method conducts the Diffie-Hellman Group Key Exchange with the remote party.
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
				await _sshClient.Log("DiffieHellmanGroupKeyExchange Selected");
                // Begin waiting for the GroupMessage.
                var groupMessageTask = GetGroupMessageAsync();

                // Send the request message to begin the Diffie-Hellman Group Key Exchange.
                await SendRequestMessageAsync();

                // Receive the 'Group' Message.
                var groupMessage = await groupMessageTask;

                // Generate random number 'x'.
                var x = GenerateRandomBigInteger(1, (groupMessage.P - 1) / 2);

                // Generate 'e'.
                var e = BigInteger.ModPow(groupMessage.G, x, groupMessage.P);

                // Begin waiting for the ReplyMessage.
                var replyMessageTask = GetReplyMessageAsync();

                // Send 'e' to the server with the 'Init' message.
                await SendInitMessageAsync(e);

                // Receive the 'Reply' message.
                var replyMessage = await replyMessageTask;

                // Verify 'F' is in the range of [1, p-1]
                if (replyMessage.F < 1 || replyMessage.F > groupMessage.P - 1)
                {
					await _sshClient.Log("Invalid 'F' from server!");
                    throw new SshException("Invalid 'F' from server!");
                }

                // Generate the shared secret 'K'
                K = BigInteger.ModPow(replyMessage.F, x, groupMessage.P);

                // Prepare the signing algorithm from the servers public key.
                _signingAlgorithm = Signer.CreateSigner(_kexInitExchangeResult.ServerHostKeyAlgorithm, replyMessage.ServerPublicHostKeyAndCertificates);

                // Generate 'H', the computed hash. If data has been tampered via man-in-the-middle-attack 'H' will be incorrect and the connection will be terminated.
                using (var memoryStream = new MemoryStream(65535))
                {
                    memoryStream.WriteString(_sshClient.ConnectionInfo.ClientVersion);
                    memoryStream.WriteString(_sshClient.ConnectionInfo.ServerVersion);
                    memoryStream.WriteBinaryString(_kexInitExchangeResult.Client.GetBytes());
                    memoryStream.WriteBinaryString(_kexInitExchangeResult.Server.GetBytes());
                    memoryStream.WriteBinaryString(replyMessage.ServerPublicHostKeyAndCertificates);
                    memoryStream.WriteUInt(1024);
                    memoryStream.WriteUInt(2048);
                    memoryStream.WriteUInt(8192);
                    memoryStream.WriteBigInteger(groupMessage.P);
                    memoryStream.WriteBigInteger(groupMessage.G);
                    memoryStream.WriteBigInteger(e);
                    memoryStream.WriteBigInteger(replyMessage.F);
                    memoryStream.WriteBigInteger(K);

                    H = Hash(memoryStream.ToArray());

                    // Use the signing algorithm to verify the data sent by the server is correct.
                    if (!_signingAlgorithm.VerifySignature(H, replyMessage.HSignature))
                    {
						await _sshClient.Log("Invalid Host Signature");
                        throw new SshException("Invalid Host Signature.");
                    }
                }
            }
            catch (Exception ex)
            {
				await _sshClient.Log("Key Exchange Failed");
                await _sshClient.Disconnect(Disconnect.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, ex);
            }
        }

        /// <summary>
        /// Gets the 'group' message from the server.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        /// <exception cref="SshException">
        /// Throws an SshException if the server not does respond with the appropriate message.
        /// </exception>
        public async Task<DhgGroup> GetGroupMessageAsync()
        {
            var groupMessageEvent = await GetDiffieHellmanGroupMessageAsync();
            if (groupMessageEvent.Type != MessageType.SSH_MSG_KEX_Exchange_31)
            {
                throw new SshException("The remote party sent an unexpected message during the key exchange. The Diffie-Hellman Group Key Exchange has failed.");
            }

            return new DhgGroup(groupMessageEvent.Buffer);
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
        public async Task<DhgReply> GetReplyMessageAsync()
        {
            var replyMessageEvent = await GetDiffieHellmanGroupMessageAsync();
            if (replyMessageEvent.Type != MessageType.SSH_MSG_KEX_Exchange_33)
            {
                throw new SshException("The remote party sent an unexpected message during the key exchange. The Diffie-Hellman Group Key Exchange has failed.");
            }

            return new DhgReply(replyMessageEvent.Buffer);
        }

        /// <summary>
        /// Sends the 'init' message to the server.
        /// </summary>
        /// <param name="e">
        /// e = g^x mod p.
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public Task SendInitMessageAsync(BigInteger e)
        {
            return _sshClient.WriteMessage(new DhgInit(e));
        }

        /// <summary>
        /// The send request.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public Task SendRequestMessageAsync()
        {
            return _sshClient.WriteMessage(new DhgRequest(MinimumGroupSize, PreferredGroupSize, MaximumGroupSize));
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
            switch (_shaVersion)
            {
                case "SHA1":
                    return SHA1.Create();
                case "SHA256":
                    return SHA256.Create();
                default:
                    throw new SshException("Invalid SHA Specified");
            }
        }

        /// <summary>
        /// Gets a message expected by the Diffie-Hellman Group Exchange.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        private async Task<MessageEvent> GetDiffieHellmanGroupMessageAsync()
        {
            // If the message is not received within 1 minute, an exception will be thrown and the connection will be terminated.
            using (var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                return await _sshClient.GetMessageAsync(m => m.Type == MessageType.SSH_MSG_KEX_Exchange_31 || m.Type == MessageType.SSH_MSG_KEX_Exchange_33,  cancellationTokenSource.Token);
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
        private byte[] Hash(byte[] data)
        {
            using (var shaGenerator = CreateHashAlgorithm())
            {
                return shaGenerator.ComputeHash(data);
            }
        }
    }
}