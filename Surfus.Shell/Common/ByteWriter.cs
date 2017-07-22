using System;
using System.Collections.Generic;
using System.Text;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell
{
    /// <summary>
    /// Writes data to a pre-defined byte array.
    /// </summary>
    internal class ByteWriter
    {
        /// <summary>
        /// The internal byte array.
        /// </summary>
        public byte[] Bytes { get; }

        /// <summary>
        /// The current write-position of the ByteArray.
        /// </summary>
        public int Position { get; private set; }

        /// <summary>
        /// Constructs a new ByteWriter with an array of the provided sie.
        /// </summary>
        /// <param name="size"></param>
        internal ByteWriter(int size)
        {
            Bytes = new byte[size];
        }

        /// <summary>
        /// Writes a single byte to the array.
        /// </summary>
        /// <param name="value"></param>
        internal void WriteByte(byte value)
        {
            Bytes[Position++] = value;
        }

        /// <summary>
        /// Writes an unsigned integer to the byte array.
        /// </summary>
        /// <param name="value"></param>
        internal void WriteUint(uint value)
        {
            if (BitConverter.IsLittleEndian)
            {
                Bytes[Position++] = (byte)(value >> 24);
                Bytes[Position++] = (byte)(value >> 16);
                Bytes[Position++] = (byte)(value >> 8);
                Bytes[Position++] = (byte)value;
            }
            else
            {
                Bytes[Position++] = (byte)value;
                Bytes[Position++] = (byte)(value >> 24);
                Bytes[Position++] = (byte)(value >> 16);
                Bytes[Position++] = (byte)(value >> 8);
            }
        }

        /// <summary>
        /// Writes a binary string to the byte array.
        /// </summary>
        /// <param name="binaryString"></param>
        internal void WriteBinaryString(byte[] binaryString)
        {
            WriteUint((uint)binaryString.Length);
            Array.Copy(binaryString, 0, Bytes, Position, binaryString.Length);
            Position += binaryString.Length;
        }

        /// <summary>
        /// Writes a binary blob to the byte array.
        /// </summary>
        /// <param name="byteBlob"></param>
        internal void WriteByteBlob(byte[] byteBlob)
        {
            Array.Copy(byteBlob, 0, Bytes, Position, byteBlob.Length);
            Position += byteBlob.Length;
        }

        /// <summary>
        /// Writes a binary blob to the byte array.
        /// </summary>
        /// <param name="byteBlob"></param>
        internal void WriteByteBlob(ArraySegment<byte> byteBlob)
        {
            Array.Copy(byteBlob.Array, byteBlob.Offset, Bytes, Position, byteBlob.Count);
            Position += byteBlob.Count;
        }

        /// <summary>
        /// Writes a UTF8 string to the byte array.
        /// </summary>
        /// <param name="utf8String"></param>
        internal void WriteString(string utf8String)
        {
            var totalBytes = Encoding.UTF8.GetBytes(utf8String, 0, utf8String.Length, Bytes, Position + 4);
            WriteUint((uint)totalBytes);
            Position += totalBytes;
        }

        /// <summary>
        /// Writes an ASCII string to the byte array.
        /// </summary>
        /// <param name="asciiString"></param>
        internal void WriteAsciiString(string asciiString)
        {
            var totalBytes = Encoding.ASCII.GetBytes(asciiString, 0, asciiString.Length, Bytes, Position + 4);
            WriteUint((uint)totalBytes);
            Position += totalBytes;
        }

        /// <summary>
        /// Writes a KexInit to the byte array.
        /// </summary>
        /// <param name="kexInit"></param>
        /// <param name="size"></param>
        internal void WriteKexInitBinaryString(KexInit kexInit)
        {
            WriteUint((uint)kexInit.GetSize());
            kexInit.WriteBytes(this);
        }

        /// <summary>
        /// Writes a BigInteger to the byte array.
        /// </summary>
        /// <param name="bigInt"></param>
        internal void WriteBigInteger(BigInt bigInt)
        {
            WriteUint((uint)bigInt.Length);

            // Write to buffer backwards
            for (var i = 0; i != bigInt.Length; i++)
            {
                Bytes[Position + i] = bigInt.Buffer[bigInt.Length - i - 1];
            }

            Position += bigInt.Length;
        }

        /// <summary>
        /// Writes a NameList to the byte array.
        /// </summary>
        /// <param name="nameList"></param>
        internal void WriteNameList(NameList nameList)
        {
            if (nameList.IsEmpty)
            {
                WriteUint(0);
                return;
            }

            WriteAsciiString(nameList.AsString);
        }
    }
}
