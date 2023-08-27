using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class ECDsaSha2Nistp521 : ECDsaBase
    {
        public ECDsaSha2Nistp521(byte[] publicCertificate)
            : base(publicCertificate) { }

        public override string Name { get; } = "ecdsa-sha2-nistp521";

        public override ECCurve Curve => ECCurve.NamedCurves.nistP521;

        public override string CurveName { get; } = "nistp521";

        public override HashAlgorithmName HashName => HashAlgorithmName.SHA512;
    }
}
