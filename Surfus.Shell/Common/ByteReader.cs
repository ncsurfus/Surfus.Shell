using System;
using System.Numerics;
using System.Text;
using Surfus.Shell.Extensions;

namespace Surfus.Shell
{
    /// <summary>
    /// Reads data from a byte buffer.
    /// </summary>
    internal class ByteReader
    {
        /// <summary>
        /// The internal byte buffer.
        /// </summary>
        public ReadOnlyMemory<byte> Bytes { get; }

        /// <summary>
        /// The current position in the buffer.
        /// </summary>
        public int Position { get; private set; }

        internal ByteReader(byte[] bytes)
        {
            Bytes = bytes;
        }

        internal ByteReader(byte[] bytes, int index)
        {
            Bytes = bytes;
            Position = index;
        }

        private ReadOnlySpan<byte> Span => Bytes.Span;

        internal byte[] Read(int amount)
        {
            var buffer = Span.Slice(Position, amount).ToArray();
            Position += amount;
            return buffer;
        }

        internal byte ReadByte()
        {
            return Span[Position++];
        }

        internal bool ReadBoolean()
        {
            return Span[Position++] == 1;
        }

        internal uint ReadUInt32()
        {
            var span = Span;
            uint value;
            if (BitConverter.IsLittleEndian)
            {
                value = (uint)(span[Position] << 24 | span[Position + 1] << 16 | span[Position + 2] << 8 | span[Position + 3]);
            }
            else
            {
                value = (uint)(span[Position] | span[Position + 1] << 8 | span[Position + 2] << 16 | span[Position + 3] << 24);
            }

            Position += 4;
            return value;
        }

        internal static uint ReadUInt32(ReadOnlySpan<byte> buffer, int index)
        {
            if (BitConverter.IsLittleEndian)
            {
                return (uint)(buffer[index] << 24 | buffer[index + 1] << 16 | buffer[index + 2] << 8 | buffer[index + 3]);
            }
            return (uint)(buffer[index] | buffer[index + 1] << 8 | buffer[index + 2] << 16 | buffer[index + 3] << 24);
        }

        internal NameList ReadNameList()
        {
            return new NameList(ReadString()?.Split(','));
        }

        internal BigInt ReadBigInteger()
        {
            var span = Span;
            var length = (int)ReadUInt32();

            var bigIntegerBuffer = span[length + Position - 1] <= 127 ? new byte[length] : new byte[length + 1];

            for (var i = 0; i != length; i++)
            {
                bigIntegerBuffer[i] = span[Position + length - i - 1];
            }

            Position += length;
            return new BigInt(new BigInteger(bigIntegerBuffer), bigIntegerBuffer, length);
        }

        internal static BigInteger ReadBigInteger(ReadOnlySpan<byte> bytes, int position, int length)
        {
            var bigIntegerBuffer = bytes[length + position - 1] <= 127 ? new byte[length] : new byte[length + 1];

            for (var i = 0; i != length; i++)
            {
                bigIntegerBuffer[i] = bytes[position + length - i - 1];
            }

            return new BigInteger(bigIntegerBuffer);
        }

        internal static BigInteger ReadBigInteger(byte[] buffer)
        {
            if (buffer[buffer.Length - 1] <= 127)
            {
                Array.Reverse(buffer);
                return new BigInteger(buffer);
            }
            Array.Resize(ref buffer, buffer.Length + 1);

            return new BigInteger(buffer);
        }

        internal string ReadString()
        {
            var length = (int)ReadUInt32();
            var str = length != 0 ? Encoding.UTF8.GetString(Span.Slice(Position, length)) : null;
            Position += length;
            return str;
        }

        internal string ReadAsciiString()
        {
            var length = (int)ReadUInt32();
            var str = length != 0 ? Encoding.ASCII.GetString(Span.Slice(Position, length)) : null;
            Position += length;
            return str;
        }

        internal byte[] ReadBinaryString()
        {
            var length = (int)ReadUInt32();
            var binaryString = Span.Slice(Position, length).ToArray();
            Position += length;
            return binaryString;
        }

        internal byte[] ReadRsaParameter()
        {
            var span = Span;
            var length = (int)ReadUInt32();
            var offset = 0;
            if (span[Position] == 0)
            {
                offset = 1;
            }
            var binaryString = span.Slice(Position + offset, length - offset).ToArray();
            Position += length;
            return binaryString;
        }
    }
}
