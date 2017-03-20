using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using System.Security.Cryptography;

namespace Surfus.Shell.Signing
{
    public sealed class SshDss : Signer
    {

        public SshDss(byte[] signature)
		{
            Raw = signature;
            using(var memoryStream = new MemoryStream(signature))
            {
                if (Name != memoryStream.ReadString())
                {
                    throw new Exception($"Expected {Name} signature type");
                }

                var p = memoryStream.ReadBinaryString();
                var q = memoryStream.ReadBinaryString();
                var g = memoryStream.ReadBinaryString();
                var y = memoryStream.ReadBinaryString();

                DsaParameters = new DSAParameters
                {
                    P = p[0] != 0 ? p : p.Skip(1).ToArray(),
                    Q = q[0] != 0 ? q : q.Skip(1).ToArray(),
                    G = g[0] != 0 ? g : g.Skip(1).ToArray(),
                    Y = y[0] != 0 ? y : y.Skip(1).ToArray()
                };

                P = CreateBigInteger.FromUnsignedBigEndian(DsaParameters.P);
                Q = CreateBigInteger.FromUnsignedBigEndian(DsaParameters.Q);
                G = CreateBigInteger.FromUnsignedBigEndian(DsaParameters.G);
                Y = CreateBigInteger.FromUnsignedBigEndian(DsaParameters.Y);
            }
        }

        public BigInteger P { get; }
        public BigInteger Q { get; }
        public BigInteger G { get; }
        public BigInteger Y { get; }
        public DSAParameters DsaParameters { get; }

        public override string Name { get; } = "ssh-dss";
        public override byte[] Raw { get; }

        public override int GetKeySize()
        {
            using (var provider = new DSACryptoServiceProvider())
            {
                return provider.KeySize;
            }
        }

        public override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var provider = new DSACryptoServiceProvider())
            using (var memoryStream = new MemoryStream(signature))
            {
                provider.ImportParameters(DsaParameters);
                var header = memoryStream.ReadString();
                if (Name != header)
                {
                    throw new SshException("Invalid ssh-dss header.");
                }

                return provider.VerifyData(data, memoryStream.ReadBinaryString());
            }
        }
    }
}
