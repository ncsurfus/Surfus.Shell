using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class SshRsa : Signer
    {
        public SshRsa(byte[] publicCertificate)
        {
            var reader = new ByteReader(publicCertificate);
            if (Name != reader.ReadString())
            {
                throw new Exception($"Expected {Name} signature type");
            }

            var exponent = reader.ReadRsaParameter();
            var modulus = reader.ReadRsaParameter();

            RsaParameters = new RSAParameters { Exponent = exponent, Modulus = modulus };

            KeySize = modulus.Length * 8;
        }

        public RSAParameters RsaParameters { get; }
        public override string Name { get; } = "ssh-rsa";
        public override int KeySize { get; }

        public override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var rsaService = RSA.Create())
            {
                var reader = new ByteReader(signature);
                rsaService.ImportParameters(RsaParameters);
                if (Name != reader.ReadString())
                {
                    throw new Exception($"Expected {Name} signature type");
                }

                return rsaService.VerifyData(data, reader.ReadBinaryString(), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
