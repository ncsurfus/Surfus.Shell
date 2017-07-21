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
            var reader = new ByteReader(signature);
		    if (Name != reader.ReadString())
		    {
		        throw new Exception($"Expected {Name} signature type");
            }

		    P = reader.ReadBigInteger();
		    Q = reader.ReadBigInteger();
		    G = reader.ReadBigInteger();
		    Y = reader.ReadBigInteger();
            KeySize = Y.ToByteArray().Length * 8;
		}

        public BigInteger P { get; }
        public BigInteger Q { get; }
        public BigInteger G { get; }
        public BigInteger Y { get; }

        public override string Name { get; } = "ssh-dss";
        public override int KeySize { get; }

        public override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var hashAlgorithm = SHA1.Create())
            {
                var reader = new ByteReader(signature);
                var hash = ByteReader.ReadBigInteger(hashAlgorithm.ComputeHash(data));

                var header = reader.ReadString();
                if (Name != header)
                {
                    throw new SshException("Invalid DSS Header.");
                }
                var blob = reader.ReadBinaryString();
                var r = ByteReader.ReadBigInteger(blob, 0, 20);
                var s = ByteReader.ReadBigInteger(blob, 20, 20);

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