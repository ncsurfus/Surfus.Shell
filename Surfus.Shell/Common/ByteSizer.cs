using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell
{
    internal static class ByteSizer
    {
        internal static int GetByteSize()
        {
            return 1;
        }

        internal static int GetBooleanSize()
        {
            return 1;
        }

        internal static int GetIntSize()
        {
            return 4;
        }

        internal static int GetNameListSize(this NameList nameList)
        {
            if (nameList.IsEmpty)
            {
                return 4;
            }

            return GetAsciiStringSize(nameList.AsString);
        }

        internal static int GetByteBlobSize(this byte[] bytes)
        {
            return bytes.Length;
        }

        internal static int GetBinaryStringSize(this byte[] bytes)
        {
            return 4 + bytes.Length;
        }

        internal static int GetBigIntegerSize(this BigInt bigInt)
        {
            return 4 + bigInt.Length;
        }

        internal static int GetAsciiStringSize(this string asciiString)
        {
            return 4 + Encoding.ASCII.GetByteCount(asciiString);
        }

        internal static int GetStringSize(this string utf8String)
        {
            return 4 + Encoding.UTF8.GetByteCount(utf8String);
        }

        internal static int GetKexInitBinaryStringSize(this KexInit kexInit)
        {
            return 4 + kexInit.GetSize();
        }
    }
}
