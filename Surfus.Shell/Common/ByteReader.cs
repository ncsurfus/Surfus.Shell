using System;
using System.Numerics;
using System.Text;
using Surfus.Shell.Extensions;

namespace Surfus.Shell
{
    /// <summary>
    /// Reads data from the byte array.
    /// </summary>
    internal class ByteReader
    {
        /// <summary>
        /// The internal byte array.
        /// </summary>
        public byte[] Bytes { get; }

        /// <summary>
        /// The current position of the byte array.
        /// </summary>
        public int Position { get; private set; }

        /// <summary>
        /// Constructs the ByteReader from the byte array.
        /// </summary>
        /// <param name="bytes">The byte array to be read.</param>
        internal ByteReader(byte[] bytes)
        {
            Bytes = bytes;
        }

        /// <summary>
        /// Constructs the ByteReader from the byte array.
        /// </summary>
        /// <param name="bytes">The byte array to be read.</param>
        /// <param name="index">The index to begin reading at.</param>
        internal ByteReader(byte[] bytes, int index)
        {
            Bytes = bytes;
            Position = index;
        }

        /// <summary>
        /// Reads a byte from the byte array.
        /// </summary>
        /// <returns></returns>
        internal byte[] Read(int amount)
        {
            var buffer = new byte[amount];
            Array.Copy(Bytes, Position, buffer, 0, amount);
            Position += amount;
            return buffer;
        }

        /// <summary>
        /// Reads a byte from the byte array.
        /// </summary>
        /// <returns></returns>
        internal byte ReadByte()
        {
            return Bytes[Position++];
        }

        /// <summary>
        /// Reads a boolean from the byte array.
        /// </summary>
        /// <returns></returns>
        internal bool ReadBoolean()
        {
            return Bytes[Position++] == 1;
        }

        /// <summary>
        /// Reads a UInt32 from the byte array.
        /// </summary>
        /// <returns></returns>
        internal uint ReadUInt32()
        {
            uint value;
            if (BitConverter.IsLittleEndian)
            {
                value = (uint)(Bytes[Position + 0] << 24 | Bytes[Position + 1] << 16 | Bytes[Position + 2] << 8 | Bytes[Position + 3]);
            }
            else
            {
                value = (uint)(Bytes[Position] | Bytes[Position + 1] << 8 | Bytes[Position + 2] << 16 | Bytes[Position + 3] << 24);
            }
            
            Position += 4;
            return value;
        }

        /// <summary>
        /// Reads a UInt32 from the byte array in a non impacting manner.
        /// </summary>
        /// <returns></returns>
        internal static uint ReadUInt32(byte[] buffer, int index)
        {
            if (BitConverter.IsLittleEndian)
            {
                return (uint) (buffer[index + 0] << 24 | buffer[index + 1] << 16 | buffer[index + 2] << 8 | buffer[index + 3]);
            }
            return (uint) (buffer[index] | buffer[index + 1] << 8 | buffer[index + 2] << 16 | buffer[index + 3] << 24);

        }

        /// <summary>
        /// Reads a 'NameList', a command delimited string, from the byte array.
        /// </summary>
        /// <returns></returns>
        internal NameList ReadNameList()
        {
            return new NameList(ReadString()?.Split(','));
        }

        /// <summary>
        /// Reads a BigInteger from the byte array.
        /// </summary>
        /// <returns></returns>
        internal BigInt ReadBigInteger()
        {
            var length = (int)ReadUInt32();

            // If the buffer represents a negative format, add an additional piece at the end (which is initialized to 0), making our number positive.
            var bigIntegerBuffer = Bytes[length + Position - 1] <= 127 ? new byte[length] : new byte[length + 1];

            // Copy to new buffer backwards.
            for (var i = 0; i != length; i++)
            {
                bigIntegerBuffer[i] = Bytes[Position + length - i - 1];
            }

            Position += length;
            return new BigInt(new BigInteger(bigIntegerBuffer), bigIntegerBuffer, length);
        }

        /// <summary>
        /// Reads a BigInteger from the byte array.
        /// </summary>
        /// <returns></returns>
        internal static BigInteger ReadBigInteger(byte[] bytes, int position, int length)
        {
            // If the buffer represents a negative format, add an additional piece at the end (which is initialized to 0), making our number positive.
            var bigIntegerBuffer = bytes[length + position - 1] <= 127 ? new byte[length] : new byte[length + 1];

            // Copy to new buffer backwards.
            for (var i = 0; i != length; i++)
            {
                bigIntegerBuffer[i] = bytes[position + length - i - 1];
            }

            return new BigInteger(bigIntegerBuffer);
        }

        /// <summary>
        /// Reads a BigInteger from the byte array. NOTE: The buffer may be mutated.
        /// </summary>
        /// <returns></returns>
        internal static BigInteger ReadBigInteger(byte[] buffer)
        {
            // If the buffer represents a negative format, add an additional piece at the end (which is initialized to 0), making our number positive.
            if(buffer[buffer.Length - 1] <= 127)
            {
                Array.Reverse(buffer);
                return new BigInteger(buffer);
            }
            Array.Resize(ref buffer, buffer.Length + 1);

            return new BigInteger(buffer);
        }

        /// <summary>
        /// Reads a UTF-8 encoded string from the byte array.
        /// </summary>
        /// <returns></returns>
        internal string ReadString()
        {
            var length = (int)ReadUInt32();
            var asciiString = length != 0 ? Encoding.UTF8.GetString(Bytes, Position, length) : null;
            Position += length;
            return asciiString;
        }

        /// <summary>
        /// Reads an ANSI encoded string from the byte array.
        /// </summary>
        /// <returns></returns>
        internal string ReadAsciiString()
        {
            var length = (int)ReadUInt32();
            var asciiString = length != 0 ? Encoding.ASCII.GetString(Bytes, Position, length) : null;
            Position += length;
            Console.WriteLine(asciiString);
            return asciiString;
        }

        /// <summary>
        /// Reads a set of chunck of bytes from the array.
        /// </summary>
        /// <returns></returns>
        internal byte[] ReadBinaryString()
        {
            var length = (int)ReadUInt32();
            var binaryString = new byte[length];
            Array.Copy(Bytes, Position, binaryString, 0, length);
            Position += length;
            return binaryString;
        }

        /// <summary>
        /// Reads an RSAParameter byte array. Very similiar to ReadBinaryString(), but skips the first item if it's a 0.
        /// </summary>
        /// <returns></returns>
        internal byte[] ReadRsaParameter()
        {
            var length = (int)ReadUInt32();
            var offset = 0;
            if (Bytes[Position] == 0)
            {
                offset = 1;
            }
            var binaryString = new byte[length - offset];
            Array.Copy(Bytes, Position + offset, binaryString, 0, length - offset);
            Position += length;
            return binaryString;
        }
    }
}
