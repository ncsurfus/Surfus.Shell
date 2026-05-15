using System;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class SshRsa : Signer
    {
        internal SshRsa(ReadOnlyMemory<byte> publicCertificate)
        {
            var reader = new SpanReader(publicCertificate.Span);
            var keyType = reader.ReadSshAsciiString();
            if (!keyType.Is("ssh-rsa"u8))
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

        public override bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            using var rsaService = RSA.Create();
            rsaService.ImportParameters(RsaParameters);

            var reader = new SpanReader(signature);
            var sigType = reader.ReadSshAsciiString();
            if (!sigType.Is("ssh-rsa"u8))
            {
                throw new Exception($"Expected {Name} signature type");
            }

            var sigData = reader.ReadBinaryString();
            return rsaService.VerifyData(data, sigData, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }
    }
}
