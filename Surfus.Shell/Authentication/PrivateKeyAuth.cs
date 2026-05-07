using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell.Authentication
{
    /// <summary>
    /// Authenticates using a private key loaded from PEM format.
    /// Supports RSA and ECDSA (nistp256/384/521) keys.
    /// </summary>
    public class PrivateKeyAuth : IAuthMethod
    {
        private readonly AsymmetricAlgorithm _key;
        private readonly string _keyType;
        private readonly byte[] _publicKeyBlob;

        /// <summary>
        /// Creates a PrivateKeyAuth from a PEM-encoded private key string.
        /// </summary>
        public PrivateKeyAuth(string pemKey)
        {
            (_key, _keyType, _publicKeyBlob) = LoadKey(pemKey);
        }

        /// <summary>
        /// Creates a PrivateKeyAuth from a PEM-encoded private key with a passphrase.
        /// </summary>
        public PrivateKeyAuth(string pemKey, string passphrase)
        {
            (_key, _keyType, _publicKeyBlob) = LoadKey(pemKey, passphrase);
        }

        /// <summary>
        /// Creates a PrivateKeyAuth from a pre-loaded asymmetric key.
        /// </summary>
        public PrivateKeyAuth(AsymmetricAlgorithm key)
        {
            _key = key;
            (_keyType, _publicKeyBlob) = DeriveKeyInfo(key);
        }

        public Task<IClientMessage> CreateRequestAsync(string username, CancellationToken cancellationToken) =>
            Task.FromResult<IClientMessage>(
                new UaRequest(username, "ssh-connection", _keyType, (ReadOnlyMemory<byte>)_publicKeyBlob, ReadOnlyMemory<byte>.Empty)
            );

        public Task<IClientMessage> HandleMessage60Async(
            string username,
            ReadOnlyMemory<byte> sessionIdentifier,
            MessageEvent messageEvent,
            CancellationToken cancellationToken
        )
        {
            var blobMem = (ReadOnlyMemory<byte>)_publicKeyBlob;
            var dataSize =
                sessionIdentifier.GetBinaryStringSize()
                + 1
                + username.GetStringSize()
                + "ssh-connection".GetAsciiStringSize()
                + "publickey".GetAsciiStringSize()
                + 1
                + _keyType.GetAsciiStringSize()
                + blobMem.GetBinaryStringSize();

            var w = new ByteWriter(dataSize);
            w.WriteBinaryString(sessionIdentifier);
            w.WriteByte(50);
            w.WriteString(username);
            w.WriteAsciiString("ssh-connection");
            w.WriteAsciiString("publickey");
            w.WriteByte(1);
            w.WriteAsciiString(_keyType);
            w.WriteBinaryString(blobMem);

            var signature = Sign(w.Bytes);
            return Task.FromResult<IClientMessage>(
                new UaRequest(username, "ssh-connection", _keyType, blobMem, (ReadOnlyMemory<byte>)signature)
            );
        }

        private byte[] Sign(byte[] data)
        {
            switch (_key)
            {
                case RSA rsa:
                    var rsaSig = rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    return WrapSignature("rsa-sha2-512", rsaSig);

                case ECDsa ecdsa:
                    var hashAlg = _keyType switch
                    {
                        "ecdsa-sha2-nistp256" => HashAlgorithmName.SHA256,
                        "ecdsa-sha2-nistp384" => HashAlgorithmName.SHA384,
                        _ => HashAlgorithmName.SHA512,
                    };
                    var ieeeSig = ecdsa.SignData(data, hashAlg);
                    var sshSig = ConvertIeeeToSshEcdsaSignature(ieeeSig);
                    return WrapSignature(_keyType, sshSig);

                default:
                    throw new NotSupportedException($"Unsupported key type: {_key.GetType().Name}");
            }
        }

        private static byte[] WrapSignature(string algorithm, byte[] sig)
        {
            var sigMem = (ReadOnlyMemory<byte>)sig;
            var size = algorithm.GetAsciiStringSize() + sigMem.GetBinaryStringSize();
            var w = new ByteWriter(size);
            w.WriteAsciiString(algorithm);
            w.WriteBinaryString(sigMem);
            return w.Bytes;
        }

        private static byte[] ConvertIeeeToSshEcdsaSignature(byte[] ieee)
        {
            var fieldSize = ieee.Length / 2;
            var rStart = TrimLeadingZerosOffset(ieee, 0, fieldSize);
            var rLen = fieldSize - rStart;
            var sStart = TrimLeadingZerosOffset(ieee, fieldSize, fieldSize);
            var sLen = fieldSize + fieldSize - sStart;

            // SSH mpint: prepend 0x00 if high bit set
            var rPad = (ieee[rStart] & 0x80) != 0 ? 1 : 0;
            var sPad = (ieee[sStart] & 0x80) != 0 ? 1 : 0;
            var rTotal = rLen + rPad;
            var sTotal = sLen + sPad;

            var buf = new byte[4 + rTotal + 4 + sTotal];
            var pos = 0;
            WriteUInt32(buf, ref pos, (uint)rTotal);
            if (rPad == 1)
            {
                buf[pos++] = 0;
            }
            Array.Copy(ieee, rStart, buf, pos, rLen);
            pos += rLen;
            WriteUInt32(buf, ref pos, (uint)sTotal);
            if (sPad == 1)
            {
                buf[pos++] = 0;
            }
            Array.Copy(ieee, sStart, buf, pos, sLen);
            return buf;
        }

        private static int TrimLeadingZerosOffset(byte[] data, int start, int length)
        {
            var end = start + length;
            while (start < end - 1 && data[start] == 0)
            {
                start++;
            }
            return start;
        }

        private static void WriteUInt32(byte[] buf, ref int pos, uint value)
        {
            buf[pos++] = (byte)(value >> 24);
            buf[pos++] = (byte)(value >> 16);
            buf[pos++] = (byte)(value >> 8);
            buf[pos++] = (byte)value;
        }

        private static (AsymmetricAlgorithm key, string keyType, byte[] publicBlob) LoadKey(string pem, string passphrase = null)
        {
            // Try RSA
            try
            {
                var rsa = RSA.Create();
                if (passphrase != null)
                {
                    rsa.ImportFromEncryptedPem(pem, passphrase);
                }
                else
                {
                    rsa.ImportFromPem(pem);
                }
                var (kt, blob) = DeriveKeyInfo(rsa);
                return (rsa, kt, blob);
            }
            catch { }

            // Try ECDSA
            try
            {
                var ecdsa = ECDsa.Create();
                if (passphrase != null)
                {
                    ecdsa.ImportFromEncryptedPem(pem, passphrase);
                }
                else
                {
                    ecdsa.ImportFromPem(pem);
                }
                var (kt, blob) = DeriveKeyInfo(ecdsa);
                return (ecdsa, kt, blob);
            }
            catch { }

            throw new NotSupportedException("Could not load private key. Supported formats: RSA, ECDSA (nistp256/384/521).");
        }

        private static (string keyType, byte[] publicBlob) DeriveKeyInfo(AsymmetricAlgorithm key)
        {
            switch (key)
            {
                case RSA rsa:
                {
                    var p = rsa.ExportParameters(false);
                    var keyType = "ssh-rsa";
                    var e = ToMpint(p.Exponent);
                    var n = ToMpint(p.Modulus);
                    var eMem = (ReadOnlyMemory<byte>)e;
                    var nMem = (ReadOnlyMemory<byte>)n;
                    var size = keyType.GetAsciiStringSize() + eMem.GetBinaryStringSize() + nMem.GetBinaryStringSize();
                    var w = new ByteWriter(size);
                    w.WriteAsciiString(keyType);
                    w.WriteBinaryString(eMem);
                    w.WriteBinaryString(nMem);
                    return (keyType, w.Bytes);
                }
                case ECDsa ecdsa:
                {
                    var p = ecdsa.ExportParameters(false);
                    var curveName = GetCurveName(p.Curve);
                    var keyType = $"ecdsa-sha2-{curveName}";
                    var q = new byte[1 + p.Q.X.Length + p.Q.Y.Length];
                    q[0] = 0x04;
                    p.Q.X.CopyTo(q, 1);
                    p.Q.Y.CopyTo(q, 1 + p.Q.X.Length);
                    var qMem = (ReadOnlyMemory<byte>)q;
                    var size = keyType.GetAsciiStringSize() + curveName.GetAsciiStringSize() + qMem.GetBinaryStringSize();
                    var w = new ByteWriter(size);
                    w.WriteAsciiString(keyType);
                    w.WriteAsciiString(curveName);
                    w.WriteBinaryString(qMem);
                    return (keyType, w.Bytes);
                }
                default:
                    throw new NotSupportedException($"Unsupported key type: {key.GetType().Name}");
            }
        }

        private static string GetCurveName(ECCurve curve)
        {
            if (curve.Oid?.Value == "1.2.840.10045.3.1.7" || curve.Oid?.FriendlyName is "NIST P-256" or "nistP256")
            {
                return "nistp256";
            }
            if (curve.Oid?.Value == "1.3.132.0.34" || curve.Oid?.FriendlyName is "NIST P-384" or "nistP384")
            {
                return "nistp384";
            }
            if (curve.Oid?.Value == "1.3.132.0.35" || curve.Oid?.FriendlyName is "NIST P-521" or "nistP521")
            {
                return "nistp521";
            }
            throw new NotSupportedException($"Unsupported EC curve: {curve.Oid?.FriendlyName ?? curve.Oid?.Value}");
        }

        /// <summary>
        /// Converts a big-endian unsigned integer byte array to SSH mpint format
        /// (prepends 0x00 if high bit is set to indicate positive).
        /// </summary>
        private static byte[] ToMpint(byte[] data)
        {
            if (data.Length > 0 && (data[0] & 0x80) != 0)
            {
                var result = new byte[data.Length + 1];
                data.CopyTo(result, 1);
                return result;
            }
            return data;
        }
    }
}
