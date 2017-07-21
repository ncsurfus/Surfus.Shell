using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Extensions
{

    internal static class MemoryStreamExtensions
    {
        internal static void Write(this MemoryStream stream, byte[] buffer)
        {
            stream.Write(buffer, 0, buffer.Length);
        }

        internal static void WriteUInt(this MemoryStream stream, uint value)
        {
            stream.Write(value.GetBigEndianBytes());
        }

        internal static void WriteString(this MemoryStream stream, string value)
        {
            stream.WriteBinaryString(!string.IsNullOrWhiteSpace(value) ? Encoding.UTF8.GetBytes(value) : new byte[] {});
        }

        internal static void WriteAsciiString(this MemoryStream stream, string value)
        {
            stream.WriteBinaryString(!string.IsNullOrWhiteSpace(value) ? Encoding.ASCII.GetBytes(value) : new byte[] { });
        }

        internal static void WriteBinaryString(this MemoryStream stream, byte[] value)
        {
            stream.WriteUInt((uint) value.Length);
            if (value.Length != 0)
            {
                stream.Write(value);
            }
        }

        internal static void WriteNameList(this MemoryStream stream, NameList nameList)
        {
            if (nameList.IsEmpty)
            {
                stream.WriteUInt(0);
                return;
            }

            stream.WriteBinaryString(nameList.AsBytes);
        }

        internal static void WriteByte(this MemoryStream stream, byte value)
        {
            stream.Write(new[] {value}, 0, 1);
        }

        internal static void WriteBigInteger(this MemoryStream stream, BigInteger bigInteger)
        {
            var bigIntegerBytes = bigInteger.ToByteArray().Reverse().ToArray();
            stream.WriteBinaryString(bigIntegerBytes);
        }
    }
}