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
using NLog;

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

        // Message Sources
        internal TaskCompletionSource<DhgGroup> DhgGroupMessage = new TaskCompletionSource<DhgGroup>();
        internal TaskCompletionSource<DhgReply> DhgReplyMessage = new TaskCompletionSource<DhgReply>();

        private static Logger logger = LogManager.GetCurrentClassLogger();

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
        public override async Task ExchangeAsync(CancellationToken cancellationToken)
        {
            logger.Trace($"{_sshClient.ConnectionInfo.Hostname} - {nameof(ExchangeAsync)}: Beginning key exchange algorithm {nameof(DiffieHellmanGroupKeyExchange)}");

            // Send the request message to begin the Diffie-Hellman Group Key Exchange.
            logger.Debug($"{_sshClient.ConnectionInfo.Hostname} - {nameof(ExchangeAsync)}: Sending DHG Request");
            await SshClientStaticThread.WriteMessageAsync(_sshClient, new DhgRequest(MinimumGroupSize, PreferredGroupSize, MaximumGroupSize), cancellationToken);

            // Get Group Message
            logger.Debug($"{_sshClient.ConnectionInfo.Hostname} - {nameof(ExchangeAsync)}: Waiting for DHG Group Response");
            var groupMessage = await DhgGroupMessage.Task;

            // Generate random number 'x'.
            var x = GenerateRandomBigInteger(1, (groupMessage.P - 1) / 2);
            logger.Trace($"{_sshClient.ConnectionInfo.Hostname} - {nameof(ExchangeAsync)}: Generated X {x}");

            // Generate 'e'.
            var e = BigInteger.ModPow(groupMessage.G, x, groupMessage.P);
            logger.Trace($"{_sshClient.ConnectionInfo.Hostname} - {nameof(ExchangeAsync)}: Generated E {e}");

            // Send 'e' to the server with the 'Init' message.
            logger.Debug($"{_sshClient.ConnectionInfo.Hostname} - {nameof(ExchangeAsync)}: Sending E");
            await SshClientStaticThread.WriteMessageAsync(_sshClient, new DhgInit(e), cancellationToken);

            // Get ReplyMessage.
            logger.Debug($"{_sshClient.ConnectionInfo.Hostname} - {nameof(ExchangeAsync)}: Waiting for DHG Reply");
            var replyMessage = await DhgReplyMessage.Task;

            // Verify 'F' is in the range of [1, p-1]
            if (replyMessage.F < 1 || replyMessage.F > groupMessage.P - 1)
            {
               // await _sshClient.Log("Invalid 'F' from server!");
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
                    //await _sshClient.Log("Invalid Host Signature");
                    throw new SshException("Invalid Host Signature.");
                }
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

        public override void SendKeyExchangeMessage30(MessageEvent message)
        {
            throw new NotImplementedException();
        }

        public override void SendKeyExchangeMessage31(MessageEvent message)
        {
            DhgGroupMessage.SetResult(new DhgGroup(message.Buffer));
        }

        public override void SendKeyExchangeMessage32(MessageEvent message)
        {
            throw new NotImplementedException();
        }

        public override void SendKeyExchangeMessage33(MessageEvent message)
        {
            DhgReplyMessage.SetResult(new DhgReply(message.Buffer));
        }

        public override void SendKeyExchangeMessage34(MessageEvent message)
        {
            throw new NotImplementedException();
        }
    }
}