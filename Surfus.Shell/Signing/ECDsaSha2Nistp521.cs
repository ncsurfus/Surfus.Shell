using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class ECDsaSha2Nistp521 : ECDsaBase
    {
        internal ECDsaSha2Nistp521(ReadOnlyMemory<byte> publicCertificate)
            : base(publicCertificate) { }

        public override string Name { get; } = "ecdsa-sha2-nistp521";
        public override ECCurve Curve => ECCurve.NamedCurves.nistP521;
        public override string CurveName { get; } = "nistp521";
        public override HashAlgorithmName HashName => HashAlgorithmName.SHA512;
        public override int FieldSizeBytes => 66;
        protected override ReadOnlySpan<byte> NameBytes => "ecdsa-sha2-nistp521"u8;
        protected override ReadOnlySpan<byte> CurveNameBytes => "nistp521"u8;
    }
}
