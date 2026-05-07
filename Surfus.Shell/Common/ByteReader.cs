using System;
using System.Numerics;
using System.Text;
using Surfus.Shell.Exceptions;
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

        internal ByteReader(ReadOnlyMemory<byte> bytes)
        {
            Bytes = bytes;
        }

        private ReadOnlySpan<byte> Span => Bytes.Span;

        private void EnsureAvailable(int bytes)
        {
            if (Position + bytes > Bytes.Length)
                throw new SshException("Malformed packet: unexpected end of data");
        }

        internal byte[] Read(int amount)
        {
            EnsureAvailable(amount);
            var buffer = Span.Slice(Position, amount).ToArray();
            Position += amount;
            return buffer;
        }

        internal byte ReadByte()
        {
            EnsureAvailable(1);
            return Span[Position++];
        }

        internal bool ReadBoolean()
        {
            EnsureAvailable(1);
            return Span[Position++] == 1;
        }

        internal uint ReadUInt32()
        {
            EnsureAvailable(4);
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

        internal static uint ReadUInt32(ReadOnlySpan<byte> buffer)
        {
            if (BitConverter.IsLittleEndian)
            {
                return (uint)(buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3]);
            }
            return (uint)(buffer[0] | buffer[1] << 8 | buffer[2] << 16 | buffer[3] << 24);
        }

        internal NameList ReadNameList()
        {
            return new NameList(ReadString()?.Split(','));
        }

        internal BigInt ReadBigInteger()
        {
            var length = (int)ReadUInt32();
            EnsureAvailable(length);
            var value = new BigInteger(Span.Slice(Position, length), isUnsigned: false, isBigEndian: true);
            Position += length;
            return new BigInt(value, length);
        }

        internal static BigInteger ReadBigInteger(ReadOnlySpan<byte> bytes)
        {
            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        internal static BigInteger ReadBigInteger(byte[] buffer)
        {
            return new BigInteger(buffer, isUnsigned: true, isBigEndian: true);
        }

        internal string ReadString()
        {
            var length = (int)ReadUInt32();
            if (length < 0)
                throw new SshException("Invalid string length in SSH message.");
            EnsureAvailable(length);
            var str = length != 0 ? Encoding.UTF8.GetString(Span.Slice(Position, length)) : null;
            Position += length;
            return str;
        }

        internal string ReadAsciiString()
        {
            var length = (int)ReadUInt32();
            if (length < 0)
                throw new SshException("Invalid string length in SSH message.");
            EnsureAvailable(length);
            var str = length != 0 ? Encoding.ASCII.GetString(Span.Slice(Position, length)) : null;
            Position += length;
            return str;
        }

        internal byte[] ReadBinaryString()
        {
            var length = (int)ReadUInt32();
            if (length < 0)
                throw new SshException("Invalid string length in SSH message.");
            EnsureAvailable(length);
            var binaryString = Span.Slice(Position, length).ToArray();
            Position += length;
            return binaryString;
        }

        internal byte[] ReadRsaParameter()
        {
            var span = Span;
            var length = (int)ReadUInt32();
            EnsureAvailable(length);
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
