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
        /// A semaphore that keeps the key exchange algorithm in check.
        /// </summary>
        private readonly SemaphoreSlim _keyExchangeAlgorithmSemaphore = new SemaphoreSlim(1, 1);

        /// <summary>
        /// The state of the Key Exchange Algorithm
        /// </summary>
        private State _keyExchangeAlgorithmState = State.Initial;

        /// <summary>
        /// The result of the KexInit exchange.
        /// </summary>
        private readonly KexInitExchangeResult _kexInitExchangeResult;

        /// <summary>
        /// The SshClient representing the SSH connection.
        /// </summary>
        private readonly SshClient _client;

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
            _client = sshClient;
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
        public override async Task InitiateKeyExchangeAlgorithmAsync(CancellationToken cancellationToken)
        {
            await _keyExchangeAlgorithmSemaphore.WaitAsync(cancellationToken);

            if(_keyExchangeAlgorithmState != State.Initial)
            {
                throw new SshException("Unexpected key exchange algorithm state"); ;
            }

            await _client.WriteMessageAsync(new DhInit(E), cancellationToken);
            _keyExchangeAlgorithmState = State.WaitingOnDhReply;

            _keyExchangeAlgorithmSemaphore.Release();
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

        public override Task<bool> SendKeyExchangeMessage30Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public override async Task<bool> SendKeyExchangeMessage31Async(MessageEvent message, CancellationToken cancellationToken)
        {
            await _keyExchangeAlgorithmSemaphore.WaitAsync(cancellationToken);

            if(_keyExchangeAlgorithmState != State.WaitingOnDhReply)
            {
                throw new SshException("Unexpected key exchange algorithm message");
            }

            var reply = new DhReply(message.Buffer);

            if(reply == null)
            {
                throw new SshException("Invalid key exchange algorithm message"); ;
            }

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

            _client.ConnectionInfo.ServerCertificate = reply.ServerPublicHostKeyAndCertificates;
            _client.ConnectionInfo.ServerCertificateSize = _signingAlgorithm.GetKeySize();

            // Generate 'H', the computed hash. If data has been tampered via man-in-the-middle-attack 'H' will be incorrect and the connection will be terminated.
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteString(_client.ConnectionInfo.ClientVersion);
                memoryStream.WriteString(_client.ConnectionInfo.ServerVersion);
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

            _keyExchangeAlgorithmState = State.Complete;

            _keyExchangeAlgorithmSemaphore.Release();

            return true;
        }

        public override Task<bool> SendKeyExchangeMessage32Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public override Task<bool> SendKeyExchangeMessage33Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public override Task<bool> SendKeyExchangeMessage34Async(MessageEvent message, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        // State represents the current state of the key exchange algorithm
        internal enum State
        {
            Initial,
            WaitingOnDhReply,
            Complete
        }
    }
}