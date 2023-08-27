using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
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
        /// The state of the Key Exchange Algorithm
        /// </summary>
        private State _keyExchangeAlgorithmState = State.Initial;

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
        /// The signing algorithm.
        /// </summary>
        private BigInt _e;

        /// <summary>
        /// The signing algorithm.
        /// </summary>
        private BigInteger _x;

        /// <summary>
        /// The DhgGroup Message
        /// </summary>
        private DhgGroup _dhgGroupMessage;

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
        /// This method conducts the Diffie-Hellman Group Key Exchange with the remote party.
        /// </summary>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        /// <exception cref="SshException">
        /// Throws an SshException if the key exchange fails.
        /// </exception>
        internal override async Task InitiateKeyExchangeAlgorithmAsync(CancellationToken cancellationToken)
        {
            if (_keyExchangeAlgorithmState != State.Initial)
            {
                throw new SshException("Unexpected key exchange algorithm state");
            }

            // Send the request message to begin the Diffie-Hellman Group Key Exchange.
            await _client
                .WriteMessageAsync(new DhgRequest(MinimumGroupSize, PreferredGroupSize, MaximumGroupSize), cancellationToken)
                .ConfigureAwait(false);

            _keyExchangeAlgorithmState = State.WaitingonDhgGroup;
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

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal override Task<bool> ProcessMessage30Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new SshUnexpectedMessage(MessageType.SSH_MSG_KEX_Exchange_30);
        }

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal override async Task<bool> ProcessMessage31Async(MessageEvent message, CancellationToken cancellationToken)
        {
            if (_keyExchangeAlgorithmState != State.WaitingonDhgGroup)
            {
                throw new SshException("Unexpected key exchange algorithm message");
            }

            _dhgGroupMessage = new DhgGroup(message.Packet);
            if (_dhgGroupMessage == null)
            {
                throw new SshException("Invalid key exchange algorithm message");
            }

            // Generate random number 'x'.
            _x = GenerateRandomBigInteger(1, (_dhgGroupMessage.P.BigInteger - 1) / 2);

            // Generate 'e'.
            _e = new BigInt(BigInteger.ModPow(_dhgGroupMessage.G.BigInteger, _x, _dhgGroupMessage.P.BigInteger));

            // Send 'e' to the server with the 'Init' message.
            await _client.WriteMessageAsync(new DhgInit(_e), cancellationToken).ConfigureAwait(false);

            _keyExchangeAlgorithmState = State.WaitingOnDhgReply;
            return false;
        }

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal override Task<bool> ProcessMessage32Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new SshUnexpectedMessage(MessageType.SSH_MSG_KEX_Exchange_32);
        }

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal override async Task<bool> ProcessMessage33Async(MessageEvent message, CancellationToken cancellationToken)
        {
            if (_keyExchangeAlgorithmState != State.WaitingOnDhgReply)
            {
                throw new SshException("Unexpected key exchange algorithm message");
            }

            var replyMessage = new DhgReply(message.Packet);
            if (replyMessage == null)
            {
                throw new SshException("Invalid key exchange algorithm message");
            }

            // Verify 'F' is in the range of [1, p-1]
            if (replyMessage.F.BigInteger < 1 || replyMessage.F.BigInteger > _dhgGroupMessage.P.BigInteger - 1)
            {
                // await _sshClient.Log("Invalid 'F' from server!");
                throw new SshException("Invalid 'F' from server!");
            }

            // Generate the shared secret 'K'
            K = new BigInt(BigInteger.ModPow(replyMessage.F.BigInteger, _x, _dhgGroupMessage.P.BigInteger));

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
                _dhgGroupMessage.P.GetBigIntegerSize()
                + _dhgGroupMessage.G.GetBigIntegerSize()
                + _e.GetBigIntegerSize()
                + replyMessage.F.GetBigIntegerSize()
                + K.GetBigIntegerSize();

            var byteWriter = new ByteWriter(totalBytes);
            byteWriter.WriteString(_client.ConnectionInfo.ClientVersion);
            byteWriter.WriteString(_client.ConnectionInfo.ServerVersion);
            byteWriter.WriteKexInitBinaryString(_kexInitExchangeResult.Client);
            byteWriter.WriteKexInitBinaryString(_kexInitExchangeResult.Server);
            byteWriter.WriteBinaryString(replyMessage.ServerPublicHostKeyAndCertificates);
            byteWriter.WriteUint(1024);
            byteWriter.WriteUint(2048);
            byteWriter.WriteUint(8192);
            byteWriter.WriteBigInteger(_dhgGroupMessage.P);
            byteWriter.WriteBigInteger(_dhgGroupMessage.G);
            byteWriter.WriteBigInteger(_e);
            byteWriter.WriteBigInteger(replyMessage.F);
            byteWriter.WriteBigInteger(K);

            H = Hash(byteWriter.Bytes);

            // Use the signing algorithm to verify the data sent by the server is correct.
            if (!_signingAlgorithm.VerifySignature(H, replyMessage.HSignature))
            {
                throw new SshException("Invalid Host Signature.");
            }

            _keyExchangeAlgorithmState = State.Complete;
            return await Task.FromResult(true);
        }

        /// <summary>
        /// Processes a key exchange message.
        /// </summary>
        /// <param name="message">The key exchange message to be processed.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Returns true if the exchange is completed and a new keys should be expected/sent.</returns>
        internal override Task<bool> ProcessMessage34Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new SshUnexpectedMessage(MessageType.SSH_MSG_KEX_Exchange_34);
        }

        /// <summary>
        /// The states of the diffie hellman group key exchange.
        /// </summary>
        internal enum State
        {
            Initial,
            WaitingonDhgGroup,
            WaitingOnDhgReply,
            Complete
        }
    }
}
