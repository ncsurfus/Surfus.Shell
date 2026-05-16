using System;
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
    public class DiffieHellmanGroupKeyExchange : KeyExchangeAlgorithm
    {
        /// <summary>
        /// The maximum group size.
        /// </summary>
        private const uint MaximumGroupSize = 8192;

        /// <summary>
        /// The minimum group size.
        /// </summary>
        private const uint MinimumGroupSize = 2048;

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
        /// The key exchange context.
        /// </summary>
        private readonly KexContext _context;

        /// <summary>
        /// The signing algorithm.
        /// </summary>
        private Signer? _signingAlgorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="DiffieHellmanGroupKeyExchange"/> class.
        /// </summary>
        /// <param name="context">
        /// The SSH client.
        /// </param>
        /// <param name="kexInitExchangeResult">
        /// The result of the KexInit exchange.
        /// </param>
        /// <param name="shaVersion">
        /// The SHA version. Can be 'SHA1' or 'SHA256'.
        /// </param>
        internal DiffieHellmanGroupKeyExchange(KexContext context, KexInitExchangeResult kexInitExchangeResult, string shaVersion)
        {
            _context = context;
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

        public override async Task<KeyExchangeResult> ExchangeAsync(CancellationToken cancellationToken)
        {
            await _context
                .Inbox.SendAsync(new DhgRequest(MinimumGroupSize, PreferredGroupSize, MaximumGroupSize), cancellationToken)
                .ConfigureAwait(false);
            using var dhgGroupMessage = await _context
                .Inbox.ReadAsync(MessageType.SSH_MSG_KEX_Exchange_31, cancellationToken)
                .ConfigureAwait(false);

            var dhgGroupView = new MessageViews.KeyExchange.DhgGroupView(dhgGroupMessage.Payload);
            var p = new BigInt(dhgGroupView.P);
            var g = new BigInt(dhgGroupView.G);

            // Validate server-provided DH group parameters
            if (p.BigInteger.GetBitLength() < 2048)
            {
                throw new SshException("Server DH group P is too small (must be at least 2048 bits).");
            }
            if (p.BigInteger % 2 == 0)
            {
                throw new SshException("Server DH group P must be odd.");
            }
            if (g.BigInteger <= 1 || g.BigInteger >= p.BigInteger - 1)
            {
                throw new SshException("Server DH group G is out of valid range.");
            }

            // Generate random number 'x'.
            var x = GenerateRandomBigInteger(1, (p.BigInteger - 1) / 2);

            // Generate 'e'.
            var e = new BigInt(BigInteger.ModPow(g.BigInteger, x, p.BigInteger));

            await _context.Inbox.SendAsync(new DhgInit(e), cancellationToken).ConfigureAwait(false);
            using var dhgReplyMessage = await _context
                .Inbox.ReadAsync(MessageType.SSH_MSG_KEX_Exchange_33, cancellationToken)
                .ConfigureAwait(false);

            var replyView = new MessageViews.KeyExchange.DhgReplyView(dhgReplyMessage.Payload);
            var serverHostKey = replyView.ServerPublicHostKeyAndCertificates.ToArray();
            var f = new BigInt(replyView.F);
            var hSignature = replyView.HSignature.ToArray();

            // Verify 'F' is in the range of [1, p-1]
            if (f.BigInteger < 1 || f.BigInteger > p.BigInteger - 1)
            {
                throw new SshException("Invalid 'F' from server!");
            }

            // Generate the shared secret 'K'
            var k = new BigInt(BigInteger.ModPow(f.BigInteger, x, p.BigInteger));

            // Prepare the signing algorithm from the servers public key.
            _signingAlgorithm = _context.Algorithms.CreateSigner(
                _kexInitExchangeResult.ServerHostKeyAlgorithm,
                serverHostKey
            );

            _context.ServerCertificate = serverHostKey;
            _context.ServerCertificateSize = _signingAlgorithm.KeySize;

            if (_context.HostKeyCallback != null && !await _context.HostKeyCallback(serverHostKey, cancellationToken).ConfigureAwait(false))
            {
                throw new SshException("Rejected Host Key.");
            }

            // Generate 'H', the computed hash.
            var totalBytes =
                _context.ClientVersion.GetStringSize()
                + _context.ServerVersion.GetStringSize()
                + _kexInitExchangeResult.ClientBinaryStringSize
                + _kexInitExchangeResult.ServerBinaryStringSize
                + ((ReadOnlyMemory<byte>)serverHostKey).GetBinaryStringSize()
                + 4
                + 4
                + 4
                + // Min/Desired/Max Sizes
                p.GetBigIntegerSize()
                + g.GetBigIntegerSize()
                + e.GetBigIntegerSize()
                + f.GetBigIntegerSize()
                + k.GetBigIntegerSize();

            var byteWriter = new ByteWriter(totalBytes);
            byteWriter.WriteString(_context.ClientVersion);
            byteWriter.WriteString(_context.ServerVersion);
            byteWriter.WriteBinaryString(_kexInitExchangeResult.ClientBytes);
            byteWriter.WriteBinaryString(_kexInitExchangeResult.ServerBytes);
            byteWriter.WriteBinaryString((ReadOnlyMemory<byte>)serverHostKey);
            byteWriter.WriteUint(MinimumGroupSize);
            byteWriter.WriteUint(PreferredGroupSize);
            byteWriter.WriteUint(MaximumGroupSize);
            byteWriter.WriteBigInteger(p);
            byteWriter.WriteBigInteger(g);
            byteWriter.WriteBigInteger(e);
            byteWriter.WriteBigInteger(f);
            byteWriter.WriteBigInteger(k);

            var h = Hash(byteWriter.Bytes);

            // Use the signing algorithm to verify the data sent by the server is correct.
            if (!_signingAlgorithm.VerifySignature(h, hSignature))
            {
                throw new SshException("Invalid Host Signature.");
            }

            return new KeyExchangeResult(h, k);
        }
    }
}
