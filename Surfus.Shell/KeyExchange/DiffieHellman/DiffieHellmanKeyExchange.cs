using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.KeyExchange.DiffieHellman;
using Surfus.Shell.Signing;

namespace Surfus.Shell.KeyExchange.DiffieHellman
{
    /// <summary>
    /// Implements the Diffie-Hellman Exchange.
    /// </summary>
    public abstract class DiffieHellmanKeyExchange : KeyExchangeAlgorithm
    {
        private readonly KexContext _context;
        private readonly KexInitExchangeResult _kexInitExchangeResult;

        /// <summary>
        /// Initializes a new instance of the <see cref="DiffieHellmanKeyExchange"/> class.
        /// </summary>
        /// <param name="sshClient">
        /// The SSH client.
        /// </param>
        /// <param name="kexInitExchangeResult">
        /// The result of the KexInit exchange.
        /// </param>
        protected DiffieHellmanKeyExchange(KexContext context, KexInitExchangeResult kexInitExchangeResult)
        {
            // Per RFC 4419, the private exponent must have sufficient entropy.
            // Use at least max(256, hashOutputBits * 2) bits.
            using var hashAlg = CreateHashAlgorithm();
            var exponentBits = Math.Max(256, hashAlg.HashSize * 2);
            var minValue = BigInteger.One << (exponentBits - 1); // 2^(bits-1)
            var maxValue = (BigInteger.One << exponentBits) - 1; // 2^bits - 1
            // Clamp to [2, P-2]
            if (minValue < 2) minValue = 2;
            var pMinus2 = P.BigInteger - 2;
            if (maxValue > pMinus2) maxValue = pMinus2;

            var x = GenerateRandomBigInteger(minValue, maxValue);
            var e = BigInteger.ModPow(G.BigInteger, x, P.BigInteger);
            E = new BigInt(e);
            X = new BigInt(x);
            _context = context;
            _kexInitExchangeResult = kexInitExchangeResult;
        }

        /// <summary>
        /// MODP Group Bit Length
        /// </summary>
        protected abstract uint Bits { get; }

        /// <summary>
        /// E = g^x mod p
        /// </summary>
        protected BigInt E { get; }

        /// <summary>
        /// Gets the generator for the subgroup.
        /// </summary>
        protected virtual BigInt G { get; } = new BigInt(new byte[] { 2 });

        /// <summary>
        /// A large predefined safe prime number.
        /// </summary>
        protected abstract BigInt P { get; }

        /// <summary>
        /// A random number between [1, q]
        /// </summary>
        protected BigInt X { get; }

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
            using var shaGenerator = CreateHashAlgorithm();
            return shaGenerator.ComputeHash(data);
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

        public override async Task<KeyExchangeResult> ExchangeAsync(CancellationToken cancellationToken)
        {
            await _context.Inbox.SendAsync(new DhInit(E), cancellationToken).ConfigureAwait(false);
            var dhReplyMessage = await _context.Inbox.ReadAsync(MessageType.SSH_MSG_KEX_Exchange_31, cancellationToken).ConfigureAwait(false);
            var reply = new DhReply(dhReplyMessage.Packet);

            // Verify 'F' is in the range of [1, p-1]
            if (reply.F.BigInteger < 1 || reply.F.BigInteger > P.BigInteger - 1)
            {
                throw new SshException("Invalid 'F' from server!");
            }

            // Generate the shared secret 'K'
            var k = new BigInt(BigInteger.ModPow(reply.F.BigInteger, X.BigInteger, P.BigInteger));

            // Prepare the signing algorithm from the servers public key.
            var signingAlgorithm = _context.Algorithms.CreateSigner(
                _kexInitExchangeResult.ServerHostKeyAlgorithm,
                reply.ServerPublicHostKeyAndCertificates
            );

            _context.ServerCertificate = reply.ServerPublicHostKeyAndCertificates;
            _context.ServerCertificateSize = signingAlgorithm.KeySize;

            if (_context.HostKeyCallback != null && !_context.HostKeyCallback(reply.ServerPublicHostKeyAndCertificates))
            {
                throw new SshException("Rejected Host Key.");
            }

            // Generate 'H', the computed hash. If data has been tampered via man-in-the-middle-attack 'H' will be incorrect and the connection will be terminated.s
            var totalBytes =
                _context.ClientVersion.GetStringSize()
                + _context.ServerVersion.GetStringSize()
                + _kexInitExchangeResult.Client.GetKexInitBinaryStringSize()
                + _kexInitExchangeResult.Server.GetKexInitBinaryStringSize()
                + reply.ServerPublicHostKeyAndCertificates.GetBinaryStringSize()
                + E.GetBigIntegerSize()
                + reply.F.GetBigIntegerSize()
                + k.GetBigIntegerSize();

            var byteWriter = new ByteWriter(totalBytes);
            byteWriter.WriteString(_context.ClientVersion);
            byteWriter.WriteString(_context.ServerVersion);
            byteWriter.WriteKexInitBinaryString(_kexInitExchangeResult.Client);
            byteWriter.WriteKexInitBinaryString(_kexInitExchangeResult.Server);
            byteWriter.WriteBinaryString(reply.ServerPublicHostKeyAndCertificates);
            byteWriter.WriteBigInteger(E);
            byteWriter.WriteBigInteger(reply.F);
            byteWriter.WriteBigInteger(k);

            var h = Hash(byteWriter.Bytes);

            // Use the signing algorithm to verify the data sent by the server is correct.
            if (!signingAlgorithm.VerifySignature(h, reply.HSignature.Span))
            {
                throw new SshException("Invalid Host Signature.");
            }

            return new KeyExchangeResult(h, k);
        }
    }
}
