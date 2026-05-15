using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public abstract class ECDsaBase : Signer
    {
        internal ECDsaBase(ReadOnlyMemory<byte> publicCertificate)
        {
            var reader = new SpanReader(publicCertificate.Span);
            var keyType = reader.ReadSshAsciiString();
            if (!keyType.Is(NameBytes))
            {
                throw new Exception($"Expected {Name} signature type!");
            }

            var curveName = reader.ReadSshAsciiString();
            if (!curveName.Is(CurveNameBytes))
            {
                throw new Exception($"Expected {CurveName} curve!");
            }

            var qBytes = reader.ReadBinaryString();
            if (qBytes.Length == 0 || qBytes[0] != 0x04)
            {
                throw new Exception("Unsupported EC point format (expected uncompressed 0x04).");
            }
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

        /// <summary>UTF-8 bytes of the algorithm name for zero-alloc comparison.</summary>
        protected abstract ReadOnlySpan<byte> NameBytes { get; }

        /// <summary>UTF-8 bytes of the curve name for zero-alloc comparison.</summary>
        protected abstract ReadOnlySpan<byte> CurveNameBytes { get; }

        public override bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            using var ecdsa = ECDsa.Create(Parameters);

            var reader = new SpanReader(signature);
            var sigType = reader.ReadSshAsciiString();
            if (!sigType.Is(NameBytes))
            {
                throw new Exception($"Expected {Name} signature type!");
            }

            var blob = reader.ReadBinaryString();
            var blobReader = new SpanReader(blob);
            var r = blobReader.ReadBigInteger();
            var s = blobReader.ReadBigInteger();

            var fieldSize = FieldSizeBytes;
            var rsSignature = new byte[fieldSize * 2];
            var rBytes = (int)r.GetByteCount(true);
            var sBytes = (int)s.GetByteCount(true);
            if (rBytes > fieldSize || sBytes > fieldSize || r.Sign <= 0 || s.Sign <= 0)
                return false;
            r.TryWriteBytes(rsSignature.AsSpan(fieldSize - rBytes, rBytes), out _, true, true);
            s.TryWriteBytes(rsSignature.AsSpan(fieldSize * 2 - sBytes, sBytes), out _, true, true);

            return ecdsa.VerifyData(data, rsSignature, HashName);
        }
    }
}
