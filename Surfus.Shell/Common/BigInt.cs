using System.Numerics;

namespace Surfus.Shell
{
    /// <summary>
    /// Represents a BigInteger and any associated buffers.
    /// </summary>
    internal class BigInt
    {
        /// <summary>
        /// This should be the only type accessed directly outside of ByteReader/ByteWriter
        /// </summary>
        internal BigInteger BigInteger { get; }

        /// <summary>
        /// The Little Endian buffer of this device.
        /// </summary>
        internal byte[] Buffer { get; }

        /// <summary>
        /// Represents the length of the buffer.
        /// </summary>
        internal int Length { get; }

        public BigInt(BigInteger bigInteger, byte[] buffer, int length)
        {
            BigInteger = bigInteger;
            Buffer = buffer;
            Length = length;
        }

        public BigInt(byte[] buffer)
        {
            BigInteger = new BigInteger(buffer);
            Buffer = buffer;
            Length = Buffer.Length;
        }

        public BigInt(BigInteger bigInteger)
        {
            BigInteger = bigInteger;
            Buffer = bigInteger.ToByteArray();
            Length = Buffer.Length;
        }
    }
}
