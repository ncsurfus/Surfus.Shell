using System;
using System.Linq;
using System.Numerics;
using System.Text;
using Surfus.Shell.Extensions;

namespace Surfus.Shell
{
    /// <summary>
    /// Reads data from the byte array. The array may be modified by methods in this class.
    /// </summary>
    internal class ByteReader
    {
        /// <summary>
        /// The internal byte array.
        /// </summary>
        private readonly byte[] _bytes;

        /// <summary>
        /// The current position of the byte array.
        /// </summary>
        private int _position;

        /// <summary>
        /// Constructs the ByteReader from the byte array.
        /// </summary>
        /// <param name="bytes">The byte array to be read.</param>
        internal ByteReader(byte[] bytes)
        {
            _bytes = bytes;
        }

        /// <summary>
        /// Constructs the ByteReader from the byte array.
        /// </summary>
        /// <param name="bytes">The byte array to be read.</param>
        /// <param name="index">The index to begin reading at.</param>
        internal ByteReader(byte[] bytes, int index)
        {
            _bytes = bytes;
            _position = index;
        }

        /// <summary>
        /// Reads a byte from the byte array.
        /// </summary>
        /// <returns></returns>
        internal byte[] Read(int amount)
        {
            var buffer = new byte[amount];
            Array.Copy(_bytes, _position, buffer, 0, amount);
            _position += amount;
            return buffer;
        }

        /// <summary>
        /// Reads a byte from the byte array.
        /// </summary>
        /// <returns></returns>
        internal byte ReadByte()
        {
            return _bytes[_position++];
        }

        /// <summary>
        /// Reads a boolean from the byte array.
        /// </summary>
        /// <returns></returns>
        internal bool ReadBoolean()
        {
            return _bytes[_position++] == 1;
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
                value = (uint)(_bytes[_position + 0] << 24 | _bytes[_position + 1] << 16 | _bytes[_position + 2] << 8 | _bytes[_position + 3]);
            }
            else
            {
                value = (uint)(_bytes[_position] | _bytes[_position + 1] << 8 | _bytes[_position + 2] << 16 | _bytes[_position + 3] << 24);
            }
            
            _position += 4;
            return value;
        }

        /// <summary>
        /// Reads a UInt32 from the byte array in a non impacting manner.
        /// </summary>
        /// <returns></returns>
        internal static uint ReadUInt32Safe(byte[] buffer, int index)
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
        internal BigInteger ReadBigInteger()
        {
            var length = (int)ReadUInt32();

            // If the buffer represents a negative format, add an additional piece at the end (which is initialized to 0), making our number positive.
            var bigIntegerBuffer = _bytes[length + _position - 1] <= 127 ? new byte[length] : new byte[length + 1];

            // Copy to new buffer backwards.
            for (var i = 0; i != length; i++)
            {
                bigIntegerBuffer[i] = _bytes[_position + length - i - 1];
            }

            _position += length;
            return new BigInteger(bigIntegerBuffer);
        }

        /// <summary>
        /// Reads a BigInteger from the byte array.
        /// </summary>
        /// <returns></returns>
        internal static BigInteger ReadBigInteger(byte[] buffer, int position, int length)
        {
            // This code reverse the array AND then copies it... there must be a better way. Should I just copy this in reverse order?
            // Reverse array to the expected order.
            Array.Reverse(buffer, position, length);

            // If the buffer represents a negative format, add an additional piece at the end (which is initialized to 0), making our number positive.
            var bigIntegerBuffer = buffer[length + position - 1] <= 127 ? new byte[length] : new byte[length + 1];

            Array.Copy(buffer, position, bigIntegerBuffer, 0, length);

            return new BigInteger(bigIntegerBuffer);
        }

        /// <summary>
        /// Reads a BigInteger from the byte array.
        /// </summary>
        /// <returns></returns>
        internal static BigInteger ReadBigInteger(byte[] buffer)
        {
            // This code reverse the array AND then copies it... there must be a better way. Should I just copy this in reverse order?
            // Reverse array to the expected order.
            Array.Reverse(buffer);

            // If the buffer represents a negative format, add an additional piece at the end (which is initialized to 0), making our number positive.
            if (buffer[buffer.Length - 1] <= 127)
            {
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
            var asciiString = length != 0 ? Encoding.UTF8.GetString(_bytes, _position, length) : null;
            _position += length;
            return asciiString;
        }

        /// <summary>
        /// Reads an ANSI encoded string from the byte array.
        /// </summary>
        /// <returns></returns>
        internal string ReadAsciiString()
        {
            var length = (int)ReadUInt32();
            var asciiString = length != 0 ? Encoding.ASCII.GetString(_bytes, _position, length) : null;
            _position += length;
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
            Array.Copy(_bytes, _position, binaryString, 0, length);
            _position += length;
            return binaryString;
        }
    }
}
