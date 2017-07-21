using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;

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

            var exponent = reader.ReadBinaryString();
            var modulus = reader.ReadBinaryString();
            RsaParameters = new RSAParameters
            {
                Exponent = exponent[0] != 0 ? exponent : exponent.Skip(1).ToArray(),
                Modulus = modulus[0] != 0 ? modulus : modulus.Skip(1).ToArray()
            };
        }

        public RSAParameters RsaParameters { get; }
        public override string Name { get; } = "ssh-rsa";

        public override int GetKeySize()
        {
            using (var rsaService = RSA.Create())
            {
                rsaService.ImportParameters(RsaParameters);
                return rsaService.KeySize;
            }
        }

        public override bool VerifySignature(byte[] data, byte[] signature)
        {
			using(var rsaService = RSA.Create())
            using (var memoryStream = new MemoryStream(signature))
            {
                rsaService.ImportParameters(RsaParameters);
                if (Name != memoryStream.ReadString())
                {
                    throw new Exception($"Expected {Name} signature type");
                }

				return rsaService.VerifyData(data, memoryStream.ReadBinaryString(), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
