using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class ECDsaSha2Nistp256 : ECDsaBase
    {
        internal ECDsaSha2Nistp256(ReadOnlyMemory<byte> publicCertificate)
            : base(publicCertificate) { }

        public override string Name { get; } = "ecdsa-sha2-nistp256";
        public override ECCurve Curve => ECCurve.NamedCurves.nistP256;
        public override string CurveName { get; } = "nistp256";
        public override HashAlgorithmName HashName => HashAlgorithmName.SHA256;
        public override int FieldSizeBytes => 32;
        protected override ReadOnlySpan<byte> NameBytes => "ecdsa-sha2-nistp256"u8;
        protected override ReadOnlySpan<byte> CurveNameBytes => "nistp256"u8;
    }
}
