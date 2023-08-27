using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class ECDsaSha2Nistp384 : ECDsaBase
    {
        public ECDsaSha2Nistp384(byte[] publicCertificate)
            : base(publicCertificate) { }

        public override string Name { get; } = "ecdsa-sha2-nistp384";

        public override ECCurve Curve => ECCurve.NamedCurves.nistP384;

        public override string CurveName { get; } = "nistp384";

        public override HashAlgorithmName HashName => HashAlgorithmName.SHA384;
    }
}
