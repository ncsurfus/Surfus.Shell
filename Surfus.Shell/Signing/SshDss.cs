using System;

using Surfus.Shell.Exceptions;
using System.Security.Cryptography;
using System.Numerics;

namespace Surfus.Shell.Signing
{
    internal sealed class SshDss : Signer
    {
        public SshDss(ReadOnlyMemory<byte> signature)
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
            KeySize = Y.Buffer.Length * 8;
		}

        public BigInt P { get; }
        public BigInt Q { get; }
        public BigInt G { get; }
        public BigInt Y { get; }

        public override string Name { get; } = "ssh-dss";
        public override int KeySize { get; }

        public override bool VerifySignature(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> signature)
        {
            using (var hashAlgorithm = SHA1.Create())
            {
                var reader = new ByteReader(signature);
                var hashBytes = new byte[hashAlgorithm.HashSize / 8];
                if (!hashAlgorithm.TryComputeHash(data.Span, hashBytes, out int _))
                {
                    throw new SshException("Failed to compute hash.");
                }
                var hash = ByteReader.ReadBigInteger(hashBytes);

                var header = reader.ReadString();
                if (Name != header)
                {
                    throw new SshException("Invalid DSS Header.");
                }
                var blob = reader.ReadBinaryString();
                var r = ByteReader.ReadBigInteger(blob.Span.Slice(0, 20));
                var s = ByteReader.ReadBigInteger(blob.Span.Slice(20, 20));

                if (r <= 0 || r >= Q.BigInteger)
                {
                    throw new SshException("Invalid DSS 'R'.");
                }

                if (s <= 0 || s >= Q.BigInteger)
                {
                    throw new SshException("Invalid DSS 'S'.");
                }

                var w = ModInverse(s, Q.BigInteger);
                var u1 = hash * w % Q.BigInteger;
                var u2 = r * w % Q.BigInteger;
                u1 = BigInteger.ModPow(G.BigInteger, u1, P.BigInteger);
                u2 = BigInteger.ModPow(Y.BigInteger, u2, P.BigInteger);

                var v = ((u1 * u2) % P.BigInteger) % Q.BigInteger;

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