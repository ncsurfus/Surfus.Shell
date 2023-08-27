using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class EcdsaSha2Nistp256 : Signer
    {
        public EcdsaSha2Nistp256(byte[] publicCertificate)
        {
            var reader = new ByteReader(publicCertificate);
            if (Name != reader.ReadString())
            {
                throw new Exception($"Expected {Name} signature type!");
            }

            if (Curve != reader.ReadString())
            {
                throw new Exception($"Expected {Curve} signature type!");
            }

            // https://www.rfc-editor.org/rfc/rfc5656#section-3.1
            // TODO: Point Compression, I think?
            var qBytes = reader.ReadBinaryString().AsMemory();
            var x = qBytes.Slice(1, (qBytes.Length - 1) / 2);
            var y = qBytes.Slice(1 + x.Length, x.Length);
            Parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x.ToArray(), Y = y.ToArray() }
            };
        }

        public ECParameters Parameters { get; }
        public override string Name { get; } = "ecdsa-sha2-nistp256";

        public string Curve { get; } = "nistp256";

        public override int KeySize { get; }

        public override bool VerifySignature(byte[] data, byte[] signature)
        {
            // https://www.rfc-editor.org/rfc/rfc5656#section-3.1.2
            using var ecdsa = ECDsa.Create(Parameters);

            // Verify signature type
            var reader = new ByteReader(signature);
            if (Name != reader.ReadString())
            {
                throw new Exception($"Expected {Name} signature type!");
            }

            // Read signature blob. The signature is composed of two big integers: r and s. These
            // need to be converted into Unsigned + Big Endian for .NET to validate the signature.
            var blob = reader.ReadBinaryString();
            var blobReader = new ByteReader(blob);
            var r = blobReader.ReadBigInteger();
            var s = blobReader.ReadBigInteger();

            var rsSignature = new byte[r.BigInteger.GetByteCount(true) + s.BigInteger.GetByteCount(true)];
            r.BigInteger.TryWriteBytes(rsSignature, out var rBytes, true, true);
            s.BigInteger.TryWriteBytes(rsSignature.AsSpan(rBytes), out var _, true, true);

            return ecdsa.VerifyData(data, rsSignature, HashAlgorithmName.SHA256);
        }
    }
}
