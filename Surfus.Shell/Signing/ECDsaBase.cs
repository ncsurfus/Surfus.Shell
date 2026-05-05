using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public abstract class ECDsaBase : Signer
    {
        internal ECDsaBase(ReadOnlyMemory<byte> publicCertificate)
        {
            var reader = new ByteReader(publicCertificate);
            if (Name != reader.ReadString())
            {
                throw new Exception($"Expected {Name} signature type!");
            }

            if (CurveName != reader.ReadString())
            {
                throw new Exception($"Expected {CurveName} signature type!");
            }

            // https://www.rfc-editor.org/rfc/rfc5656#section-3.1
            // TODO: Point Compression. This is not implemented in OpenSSH and I am
            // also ignoring it here.
            var qBytes = reader.ReadBinaryString().AsMemory();
            var x = qBytes.Slice(1, (qBytes.Length - 1) / 2);
            var y = qBytes.Slice(1 + x.Length, x.Length);
            Parameters = new ECParameters
            {
                Curve = Curve,
                Q = new ECPoint { X = x.ToArray(), Y = y.ToArray() },
            };
            KeySize = x.Length * 8;
        }

        public ECParameters Parameters { get; }

        public abstract HashAlgorithmName HashName { get; }

        public abstract ECCurve Curve { get; }

        public abstract string CurveName { get; }

        public override int KeySize { get; }

        public abstract int FieldSizeBytes { get; }

        public override bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            // https://www.rfc-editor.org/rfc/rfc5656#section-3.1.2
            using var ecdsa = ECDsa.Create(Parameters);

            var reader = new ByteReader(signature.ToArray());
            if (Name != reader.ReadString())
            {
                throw new Exception($"Expected {Name} signature type!");
            }

            // r and s must each be zero-padded to the curve's field size.
            var blob = reader.ReadBinaryString();
            var blobReader = new ByteReader(blob);
            var r = blobReader.ReadBigInteger();
            var s = blobReader.ReadBigInteger();

            var fieldSize = FieldSizeBytes;
            var rsSignature = new byte[fieldSize * 2];
            var rBytes = (int)r.BigInteger.GetByteCount(true);
            var sBytes = (int)s.BigInteger.GetByteCount(true);
            r.BigInteger.TryWriteBytes(rsSignature.AsSpan(fieldSize - rBytes, rBytes), out _, true, true);
            s.BigInteger.TryWriteBytes(rsSignature.AsSpan(fieldSize * 2 - sBytes, sBytes), out _, true, true);

            return ecdsa.VerifyData(data, rsSignature, HashName);
        }
    }
}
