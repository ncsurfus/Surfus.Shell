using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.KeyExchange.Ecdh;

namespace Surfus.Shell.KeyExchange.Ecdh
{
    /// <summary>
    /// Implements ecdh-sha2-nistp256, ecdh-sha2-nistp384, and ecdh-sha2-nistp521 key exchange (RFC 5656).
    /// </summary>
    public sealed class EcdhKeyExchange : KeyExchangeAlgorithm
    {
        private readonly KexContext _context;
        private readonly KexInitExchangeResult _kexInitExchangeResult;
        private readonly ECCurve _curve;
        private readonly HashAlgorithmName _hashName;

        internal EcdhKeyExchange(KexContext context, KexInitExchangeResult kexInitExchangeResult, ECCurve curve, HashAlgorithmName hashName)
        {
            _context = context;
            _kexInitExchangeResult = kexInitExchangeResult;
            _curve = curve;
            _hashName = hashName;
        }

        protected override HashAlgorithm CreateHashAlgorithm()
        {
            return _hashName.Name switch
            {
                "SHA256" => SHA256.Create(),
                "SHA384" => SHA384.Create(),
                "SHA512" => SHA512.Create(),
                _ => throw new SshException("Unsupported hash algorithm.")
            };
        }

        public override async Task<KeyExchangeResult> ExchangeAsync(CancellationToken cancellationToken)
        {
            using var ecdh = ECDiffieHellman.Create(_curve);
            var clientPublicKey = ecdh.PublicKey.ExportSubjectPublicKeyInfo();

            // Export the uncompressed EC point (0x04 || X || Y)
            var ecParams = ecdh.ExportParameters(false);
            var pointSize = 1 + ecParams.Q.X!.Length + ecParams.Q.Y!.Length;
            var qC = new byte[pointSize];
            qC[0] = 0x04;
            ecParams.Q.X.CopyTo(qC.AsSpan(1));
            ecParams.Q.Y.CopyTo(qC.AsSpan(1 + ecParams.Q.X.Length));

            await _context.Inbox.SendAsync(new EcdhInit(qC), cancellationToken).ConfigureAwait(false);

            var replyMessage = await _context.Inbox.ReadAsync(MessageType.SSH_MSG_KEX_Exchange_31, cancellationToken).ConfigureAwait(false);
            var reply = new EcdhReply(replyMessage.Packet);

            // Parse server's public key (uncompressed point)
            var qS = reply.ServerPublicKey.Span;
            if (qS[0] != 0x04)
            {
                throw new SshException("Server ECDH public key is not in uncompressed format.");
            }

            var coordLen = (qS.Length - 1) / 2;
            var serverParams = new ECParameters
            {
                Curve = _curve,
                Q = new ECPoint
                {
                    X = qS.Slice(1, coordLen).ToArray(),
                    Y = qS.Slice(1 + coordLen, coordLen).ToArray()
                }
            };

            using var serverKey = ECDiffieHellman.Create(serverParams);
            var sharedSecret = ecdh.DeriveRawSecretAgreement(serverKey.PublicKey);

            // Shared secret K is an mpint (strip leading zeros, ensure positive)
            var k = new BigInt(new BigInteger(sharedSecret, isUnsigned: true, isBigEndian: true));

            var signingAlgorithm = _context.Algorithms.CreateSigner(
                _kexInitExchangeResult.ServerHostKeyAlgorithm,
                reply.ServerPublicHostKeyAndCertificates
            );

            _context.ServerCertificate = reply.ServerPublicHostKeyAndCertificates;
            _context.ServerCertificateSize = signingAlgorithm.KeySize;

            if (_context.HostKeyCallback != null && !await _context.HostKeyCallback(reply.ServerPublicHostKeyAndCertificates, cancellationToken).ConfigureAwait(false))
            {
                throw new SshException("Rejected Host Key.");
            }

            // Compute exchange hash H
            var qCMem = (ReadOnlyMemory<byte>)qC;
            var totalBytes =
                _context.ClientVersion.GetStringSize()
                + _context.ServerVersion.GetStringSize()
                + _kexInitExchangeResult.Client.GetKexInitBinaryStringSize()
                + _kexInitExchangeResult.Server.GetKexInitBinaryStringSize()
                + reply.ServerPublicHostKeyAndCertificates.GetBinaryStringSize()
                + qCMem.GetBinaryStringSize()
                + reply.ServerPublicKey.GetBinaryStringSize()
                + k.GetBigIntegerSize();

            var byteWriter = new ByteWriter(totalBytes);
            byteWriter.WriteString(_context.ClientVersion);
            byteWriter.WriteString(_context.ServerVersion);
            byteWriter.WriteKexInitBinaryString(_kexInitExchangeResult.Client);
            byteWriter.WriteKexInitBinaryString(_kexInitExchangeResult.Server);
            byteWriter.WriteBinaryString(reply.ServerPublicHostKeyAndCertificates);
            byteWriter.WriteBinaryString(qCMem);
            byteWriter.WriteBinaryString(reply.ServerPublicKey);
            byteWriter.WriteBigInteger(k);

            byte[] h;
            using (var hashAlg = CreateHashAlgorithm())
            {
                h = hashAlg.ComputeHash(byteWriter.Bytes);
            }

            if (!signingAlgorithm.VerifySignature(h, reply.HSignature.Span))
            {
                throw new SshException("Invalid Host Signature.");
            }

            CryptographicOperations.ZeroMemory(sharedSecret);

            return new KeyExchangeResult(h, k);
        }
    }
}
