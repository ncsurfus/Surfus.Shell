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

        internal static byte[] ReadBytes(this MemoryStream stream, int length)
        {
            var buffer = new byte[length];
            var totalBytesread = stream.Read(buffer, 0, length);
            return totalBytesread == length ? buffer : throw new SshException("Not enough data in message!");
        }

        internal static bool ReadBoolean(this MemoryStream stream)
        {
            return stream.ReadByte() != 0;
        }

        internal static ushort ReadUInt16(this MemoryStream stream)
        {
                var data = stream.ReadBytes(2);
            return (ushort) (data[0] << 8 | data[1]);
        }

        internal static uint ReadUInt32(this MemoryStream stream)
        {
            var data = stream.ReadBytes(4);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(data);
            }
            return BitConverter.ToUInt32(data, 0);
        }

        internal static ulong ReadUInt64(this MemoryStream stream)
        {
            var data = stream.ReadBytes(8);
            return (ulong) data[0] << 56 | (ulong) data[1] << 48 | (ulong) data[2] << 40 | (ulong) data[3] << 32 |
                   (ulong) data[4] << 24 | (ulong) data[5] << 16 | (ulong) data[6] << 8 | data[7];
        }

        internal static long ReadInt64(this MemoryStream stream)
        {
            var data = stream.ReadBytes(8);
            return data[0] << 56 | data[1] << 48 | data[2] << 40 | data[3] << 32 | data[4] << 24 | data[5] << 16 |
                   data[6] << 8 | data[7];
        }

        internal static string ReadString(this MemoryStream stream)
        {
            var stringBuffer = stream.ReadBinaryString();
            return stringBuffer.Length != 0 ? Encoding.UTF8.GetString(stringBuffer) : null;
        }

        internal static string ReadAsciiString(this MemoryStream stream)
        {
            var stringBuffer = stream.ReadBinaryString();
            return stringBuffer.Length != 0 ? Encoding.ASCII.GetString(stringBuffer) : null;
        }

        internal static byte[] ReadBinaryString(this MemoryStream stream)
        {
            var length = stream.ReadUInt32();
            return length != 0 ? stream.ReadBytes((int)length) : new byte[] {};
        }
    }
}