using System;
using System.Linq;
using System.Numerics;

namespace Surfus.Shell.Extensions
{
    public static class CreateBigInteger
    {
        public static BigInteger FromUnsignedBigEndian(byte[] bigEndianByteArray)
        {
            var littleEndianByteArray = bigEndianByteArray.Reverse().ToArray();
            if (littleEndianByteArray[littleEndianByteArray.Length - 1] <= 127) return new BigInteger(littleEndianByteArray);

            Array.Resize(ref littleEndianByteArray, littleEndianByteArray.Length + 1);
            littleEndianByteArray[littleEndianByteArray.Length - 1] = 0;
            return new BigInteger(littleEndianByteArray);
        }
    }
}
