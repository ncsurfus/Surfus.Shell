using System.Numerics;

namespace Surfus.Shell
{
    internal class BigInt
    {
        internal BigInteger BigInteger { get; }
        internal byte[] Buffer { get; }

        public BigInt(BigInteger bigInteger, byte[] buffer)
        {
            BigInteger = bigInteger;
            Buffer = buffer;
        }

        public BigInt(byte[] buffer)
        {
            BigInteger = new BigInteger(buffer);
            Buffer = buffer;
        }

        public BigInt(BigInteger bigInteger)
        {
            BigInteger = bigInteger;
            Buffer = bigInteger.ToByteArray();
        }
    }
}
