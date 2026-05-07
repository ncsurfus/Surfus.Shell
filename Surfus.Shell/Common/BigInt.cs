using System.Numerics;

namespace Surfus.Shell
{
    /// <summary>
    /// Represents a BigInteger and its SSH wire-format length.
    /// </summary>
    public record BigInt
    {
        /// <summary>
        /// The BigInteger value.
        /// </summary>
        internal BigInteger BigInteger { get; }

        /// <summary>
        /// The signed big-endian byte count (SSH wire length).
        /// </summary>
        internal int Length { get; }

        internal BigInt(BigInteger bigInteger, int wireLength)
        {
            BigInteger = bigInteger;
            Length = wireLength;
        }

        internal BigInt(BigInteger bigInteger)
        {
            BigInteger = bigInteger;
            Length = bigInteger.GetByteCount(isUnsigned: false);
        }
    }
}
