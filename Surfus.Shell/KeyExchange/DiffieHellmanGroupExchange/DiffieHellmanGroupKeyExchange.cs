using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
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
        private readonly SshClient _client;

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
        internal DiffieHellmanGroupKeyExchange(SshClient sshClient, KexInitExchangeResult kexInitExchangeResult, string shaVersion)
        {
            _client = sshClient;
            _kexInitExchangeResult = kexInitExchangeResult;
            _shaVersion = shaVersion;
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
            return _shaVersion switch
            {
                "SHA1" => SHA1.Create(),
                "SHA256" => SHA256.Create(),
                _ => throw new SshException("Invalid SHA Specified"),
            };
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
            using var shaGenerator = CreateHashAlgorithm();
            return shaGenerator.ComputeHash(data);
        }

        public override async Task<KeyExchangeResult> ExchangeAsync(
            ChannelReader<MessageEvent> channelReader,
            CancellationToken cancellationToken
        )
        {
            // Send the initial 'Request' message, which sets up the parameters for the key exchange.
            await _client
                .WriteMessageAsync(new DhgRequest(MinimumGroupSize, PreferredGroupSize, MaximumGroupSize), cancellationToken)
                .ConfigureAwait(false);
            var dhgGroupMessage = await channelReader.ReadAsync(MessageType.SSH_MSG_KEX_Exchange_31, cancellationToken);
            var dhgGroup = new DhgGroup(dhgGroupMessage.Packet);

            // Generate random number 'x'.
            var x = GenerateRandomBigInteger(1, (dhgGroup.P.BigInteger - 1) / 2);

            // Generate 'e'.
            var e = new BigInt(BigInteger.ModPow(dhgGroup.G.BigInteger, x, dhgGroup.P.BigInteger));

            // Send 'e' to the server with the 'Init' message and receive the reply.
            await _client.WriteMessageAsync(new DhgInit(e), cancellationToken).ConfigureAwait(false);
            var dhgReplyMessage = await channelReader.ReadAsync(MessageType.SSH_MSG_KEX_Exchange_33, cancellationToken);
            var replyMessage = new DhgReply(dhgReplyMessage.Packet);

            // Verify 'F' is in the range of [1, p-1]
            if (replyMessage.F.BigInteger < 1 || replyMessage.F.BigInteger > dhgGroup.P.BigInteger - 1)
            {
                throw new SshException("Invalid 'F' from server!");
            }

            // Generate the shared secret 'K'
            var k = new BigInt(BigInteger.ModPow(replyMessage.F.BigInteger, x, dhgGroup.P.BigInteger));

            // Prepare the signing algorithm from the servers public key.
            _signingAlgorithm = Signer.CreateSigner(
                _kexInitExchangeResult.ServerHostKeyAlgorithm,
                replyMessage.ServerPublicHostKeyAndCertificates
            );

            _client.ConnectionInfo.ServerCertificate = replyMessage.ServerPublicHostKeyAndCertificates;
            _client.ConnectionInfo.ServerCertificateSize = _signingAlgorithm.KeySize;

            // Generate 'H', the computed hash. If data has been tampered via man-in-the-middle-attack 'H' will be incorrect and the connection will be terminated.
            var totalBytes =
                _client.ConnectionInfo.ClientVersion.GetStringSize()
                + _client.ConnectionInfo.ServerVersion.GetStringSize()
                + _kexInitExchangeResult.Client.GetKexInitBinaryStringSize()
                + _kexInitExchangeResult.Server.GetKexInitBinaryStringSize()
                + replyMessage.ServerPublicHostKeyAndCertificates.GetBinaryStringSize()
                + 4
                + 4
                + 4
                + // Min/Desired/Max Sizes
                dhgGroup.P.GetBigIntegerSize()
                + dhgGroup.G.GetBigIntegerSize()
                + e.GetBigIntegerSize()
                + replyMessage.F.GetBigIntegerSize()
                + k.GetBigIntegerSize();

            var byteWriter = new ByteWriter(totalBytes);
            byteWriter.WriteString(_client.ConnectionInfo.ClientVersion);
            byteWriter.WriteString(_client.ConnectionInfo.ServerVersion);
            byteWriter.WriteKexInitBinaryString(_kexInitExchangeResult.Client);
            byteWriter.WriteKexInitBinaryString(_kexInitExchangeResult.Server);
            byteWriter.WriteBinaryString(replyMessage.ServerPublicHostKeyAndCertificates);
            byteWriter.WriteUint(1024);
            byteWriter.WriteUint(2048);
            byteWriter.WriteUint(8192);
            byteWriter.WriteBigInteger(dhgGroup.P);
            byteWriter.WriteBigInteger(dhgGroup.G);
            byteWriter.WriteBigInteger(e);
            byteWriter.WriteBigInteger(replyMessage.F);
            byteWriter.WriteBigInteger(k);

            var h = Hash(byteWriter.Bytes);

            // Use the signing algorithm to verify the data sent by the server is correct.
            if (!_signingAlgorithm.VerifySignature(h, replyMessage.HSignature))
            {
                throw new SshException("Invalid Host Signature.");
            }

            return new KeyExchangeResult(h, k);
        }
    }
}
