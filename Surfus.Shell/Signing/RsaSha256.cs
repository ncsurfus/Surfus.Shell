using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class RsaSha256 : Signer
    {
        private string certificateNameType = "ssh-rsa";

        public RsaSha256(ReadOnlyMemory<byte> publicCertificate)
        {
            var reader = new ByteReader(publicCertificate);
            if (certificateNameType != reader.ReadString())
            {
                throw new Exception($"Expected {certificateNameType} signature type");
            }

            var exponent = reader.ReadRsaParameter();
            var modulus = reader.ReadRsaParameter();

            RsaParameters = new RSAParameters
            {
                Exponent = exponent,
                Modulus = modulus
            };

            KeySize = modulus.Length * 8;
        }

        public RSAParameters RsaParameters { get; }
        public override string Name { get; } = "rsa-sha2-256";
        public override int KeySize { get; }

        public override bool VerifySignature(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> signature)
        {
            using(var rsaService = RSA.Create())
            {
                var reader = new ByteReader(signature);
                rsaService.ImportParameters(RsaParameters);
                if (Name != reader.ReadString())
                {
                    throw new Exception($"Expected {Name} signature type");
                }

                return rsaService.VerifyData(
                    data.Span,
                    reader.ReadBinaryString().Span,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1
                );
            }
        }
    }
}
