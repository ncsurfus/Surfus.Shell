using System;
using System.Numerics;
using System.Security.Cryptography;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Signing
{
    public sealed class SshDss : Signer
    {
        internal SshDss(ReadOnlyMemory<byte> signature)
        {
            var reader = new SpanReader(signature.Span);
            var keyType = reader.ReadSshAsciiString();
            if (!keyType.Is("ssh-dss"u8))
            {
                throw new Exception($"Expected {Name} signature type");
            }

            P = reader.ReadBigInteger();
            Q = reader.ReadBigInteger();
            G = reader.ReadBigInteger();
            Y = reader.ReadBigInteger();
            KeySize = ((int)Y.GetByteCount(true)) * 8;
        }

        public BigInteger P { get; }
        public BigInteger Q { get; }
        public BigInteger G { get; }
        public BigInteger Y { get; }

        public override string Name { get; } = "ssh-dss";
        public override int KeySize { get; }

        public override bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            using var hashAlgorithm = SHA1.Create();
            var hash = new BigInteger(hashAlgorithm.ComputeHash(data.ToArray()), isUnsigned: true, isBigEndian: true);

            var reader = new SpanReader(signature);
            var header = reader.ReadSshAsciiString();
            if (!header.Is("ssh-dss"u8))
            {
                throw new SshException("Invalid DSS Header.");
            }
            var blob = reader.ReadBinaryString();
            if (blob.Length != 40)
            {
                return false;
            }
            var r = new BigInteger(blob.Slice(0, 20), isUnsigned: true, isBigEndian: true);
            var s = new BigInteger(blob.Slice(20, 20), isUnsigned: true, isBigEndian: true);

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

        private static BigInteger ModInverse(BigInteger a, BigInteger n)
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
            if (v < 0) v = (v + n) % n;
            return v;
        }
    }
}
