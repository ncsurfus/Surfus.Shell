using System;
using System.IO;
using System.Linq;

using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using System.Security.Cryptography;
using System.Numerics;

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

                P = memoryStream.ReadBigInteger();
                Q = memoryStream.ReadBigInteger();
                G = memoryStream.ReadBigInteger();
                Y = memoryStream.ReadBigInteger();
            }
        }

        public BigInteger P { get; }
        public BigInteger Q { get; }
        public BigInteger G { get; }
        public BigInteger Y { get; }

        public override string Name { get; } = "ssh-dss";
        public override byte[] Raw { get; }

        public override int GetKeySize()
        {
            return Y.ToByteArray().Length * 8;
        }

        public override bool VerifySignature(byte[] data, byte[] signature)
        {
            using(var hashAlgorithm = SHA1.Create())
            using (var memoryStream = new MemoryStream(signature))
            {
                var hash = CreateBigInteger.FromUnsignedBigEndian(hashAlgorithm.ComputeHash(data));

                var header = memoryStream.ReadString();
                if (Name != header)
                {
                    throw new SshException("Invalid DSS Header.");
                }
                var blob = memoryStream.ReadBinaryString();
                var r = CreateBigInteger.FromUnsignedBigEndian(blob.Take(20).ToArray());
                var s = CreateBigInteger.FromUnsignedBigEndian(blob.Skip(20).Take(20).ToArray());

                if (r <= 0 || r >= Q)
                {
                    throw new SshException("Invalid DSS 'R'.");
                }

                if (s <= 0 || s >= Q)
                {
                    throw new SshException("Invalid DSS 'S'.");
                }

                var w = ModInverse(s, Q);
                var u1 = hash * w % Q;
                var u2 = r * w % Q;
                u1 = BigInteger.ModPow(G, u1, P);
                u2 = BigInteger.ModPow(Y, u2, P);

                var v = ((u1 * u2) % P) % Q;
               
                return v == r;
            }
        }

        BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;

            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }

            v %= n;

            if (v < 0)
            {
                v = (v + n) % n;
            }

            return v;
        }
    }
}
