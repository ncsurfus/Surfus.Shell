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
        /// A semaphore that keeps the key exchange algorithm in check.
        /// </summary>
        private readonly SemaphoreSlim _keyExchangeAlgorithmSemaphore = new SemaphoreSlim(1, 1);

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
        private BigInteger _e;

        /// <summary>
        /// The signing algorithm.
        /// </summary>
        private BigInteger _x;

        /// <summary>
        /// The DhgGroup Message
        /// </summary>
        private DhgGroup _dhgGroupMessage;

        private Logger _logger;

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
            _client = sshClient;
            _logger = LogManager.GetLogger($"{_client.ConnectionInfo.Hostname} {_client.ConnectionInfo.Port}");
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
        public override async Task InitiateKeyExchangeAlgorithmAsync(CancellationToken cancellationToken)
        {
            await _keyExchangeAlgorithmSemaphore.WaitAsync(cancellationToken);

            if (_keyExchangeAlgorithmState != State.Initial)
            {
                throw new SshException("Unexpected key exchange algorithm state"); ;
            }

            // Send the request message to begin the Diffie-Hellman Group Key Exchange.
            await _client.WriteMessageAsync(new DhgRequest(MinimumGroupSize, PreferredGroupSize, MaximumGroupSize), cancellationToken);

            _keyExchangeAlgorithmState = State.WaitingonDhgGroup;

            _keyExchangeAlgorithmSemaphore.Release();
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

        public override Task<bool> SendKeyExchangeMessage30Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public override async Task<bool> SendKeyExchangeMessage31Async(MessageEvent message, CancellationToken cancellationToken)
        {
            await _keyExchangeAlgorithmSemaphore.WaitAsync(cancellationToken);

            if (_keyExchangeAlgorithmState != State.WaitingonDhgGroup)
            {
                throw new SshException("Unexpected key exchange algorithm message"); ;
            }

            _dhgGroupMessage = new DhgGroup(message.Buffer);
            if (_dhgGroupMessage == null)
            {
                throw new SshException("Invalid key exchange algorithm message"); ;
            }

            // Generate random number 'x'.
            _x = GenerateRandomBigInteger(1, (_dhgGroupMessage.P - 1) / 2);
            _logger.Trace($"{_client.ConnectionInfo.Hostname} - {nameof(InitiateKeyExchangeAlgorithmAsync)}: Generated X {_x}");

            // Generate 'e'.
            _e = BigInteger.ModPow(_dhgGroupMessage.G, _x, _dhgGroupMessage.P);
            _logger.Trace($"{_client.ConnectionInfo.Hostname} - {nameof(InitiateKeyExchangeAlgorithmAsync)}: Generated E {_e}");

            // Send 'e' to the server with the 'Init' message.
            _logger.Debug($"{_client.ConnectionInfo.Hostname} - {nameof(InitiateKeyExchangeAlgorithmAsync)}: Sending E");
            await _client.WriteMessageAsync(new DhgInit(_e), cancellationToken);


            _keyExchangeAlgorithmState = State.WaitingOnDhgReply;

            _keyExchangeAlgorithmSemaphore.Release();

            return false;
        }

        public override Task<bool> SendKeyExchangeMessage32Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public override async Task<bool> SendKeyExchangeMessage33Async(MessageEvent message, CancellationToken cancellationToken)
        {
            await _keyExchangeAlgorithmSemaphore.WaitAsync(cancellationToken);

            if (_keyExchangeAlgorithmState != State.WaitingOnDhgReply)
            {
                throw new SshException("Unexpected key exchange algorithm message");
            }

            var replyMessage = new DhgReply(message.Buffer);
            if (replyMessage == null)
            {
                throw new SshException("Invalid key exchange algorithm message");
            }

            // Verify 'F' is in the range of [1, p-1]
            if (replyMessage.F < 1 || replyMessage.F > _dhgGroupMessage.P - 1)
            {
                // await _sshClient.Log("Invalid 'F' from server!");
                throw new SshException("Invalid 'F' from server!");
            }

            // Generate the shared secret 'K'
            K = BigInteger.ModPow(replyMessage.F, _x, _dhgGroupMessage.P);

            // Prepare the signing algorithm from the servers public key.
            _signingAlgorithm = Signer.CreateSigner(_kexInitExchangeResult.ServerHostKeyAlgorithm, replyMessage.ServerPublicHostKeyAndCertificates);

            _client.ConnectionInfo.ServerCertificate = replyMessage.ServerPublicHostKeyAndCertificates;
            _client.ConnectionInfo.ServerCertificateSize = _signingAlgorithm.GetKeySize();

            // Generate 'H', the computed hash. If data has been tampered via man-in-the-middle-attack 'H' will be incorrect and the connection will be terminated.
            using (var memoryStream = new MemoryStream(65535))
            {
                memoryStream.WriteString(_client.ConnectionInfo.ClientVersion);
                memoryStream.WriteString(_client.ConnectionInfo.ServerVersion);
                memoryStream.WriteBinaryString(_kexInitExchangeResult.Client.GetBytes());
                memoryStream.WriteBinaryString(_kexInitExchangeResult.Server.GetBytes());
                memoryStream.WriteBinaryString(replyMessage.ServerPublicHostKeyAndCertificates);
                memoryStream.WriteUInt(1024);
                memoryStream.WriteUInt(2048);
                memoryStream.WriteUInt(8192);
                memoryStream.WriteBigInteger(_dhgGroupMessage.P);
                memoryStream.WriteBigInteger(_dhgGroupMessage.G);
                memoryStream.WriteBigInteger(_e);
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


            _keyExchangeAlgorithmState = State.Complete;

            _keyExchangeAlgorithmSemaphore.Release();

            return true;
        }

        public override Task<bool> SendKeyExchangeMessage34Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        // State represents the current state of the key exchange algorithm
        internal enum State
        {
            Initial,
            WaitingonDhgGroup,
            WaitingOnDhgReply,
            Complete
        }
    }
}