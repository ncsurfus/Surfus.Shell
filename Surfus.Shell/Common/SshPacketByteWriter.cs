using System;
using System.Text;
using Surfus.Shell.Extensions;

namespace Surfus.Shell
{
    /// <summary>
    /// Writes data to a pre-defined byte array.
    /// </summary>
    internal struct SshPacketByteWriter
    {
        /// <summary>
        /// The array to be written to.
        /// </summary>
        public byte[] Array { get; set; }

        /// <summary>
        /// The index to write in the array.
        /// </summary>
        public int Index { get; set; }

        /// <summary>
        /// Constructs a class that has useful functions for writing to arrays.
        /// </summary>
        /// <param name="array"></param>
        /// <param name="index"></param>
        public SshPacketByteWriter(byte[] array, int index)
        {
            Array = array;
            Index = index;
        }

        /// <summary>
        /// Writes a single byte to the array.
        /// </summary>
        /// <param name="value"></param>
        internal void WriteByte(byte value)
        {
            Array[Index++] = value;
        }

        /// <summary>
        /// Writes an unsigned integer to the byte array.
        /// </summary>
        /// <param name="value"></param>
        internal void WriteUint(uint value)
        {
            if (BitConverter.IsLittleEndian)
            {
                Array[Index++] = (byte)(value >> 24);
                Array[Index++] = (byte)(value >> 16);
                Array[Index++] = (byte)(value >> 8);
                Array[Index++] = (byte)value;
            }
            else
            {
                Array[Index++] = (byte)value;
                Array[Index++] = (byte)(value >> 8);
                Array[Index++] = (byte)(value >> 16);
                Array[Index++] = (byte)(value >> 24);
            }
        }

        /// <summary>
        /// Writes a binary string to the byte array.
        /// </summary>
        /// <param name="binaryString"></param>
        internal void WriteBinaryString(byte[] binaryString)
        {
            WriteUint((uint)binaryString.Length);
            System.Array.Copy(binaryString, 0, Array, Index, binaryString.Length);
            Index += binaryString.Length;
        }

        /// <summary>
        /// Writes a binary blob to the byte array.
        /// </summary>
        /// <param name="byteBlob"></param>
        internal void WriteByteBlob(byte[] byteBlob)
        {
            System.Array.Copy(byteBlob, 0, Array, Index, byteBlob.Length);
            Index += byteBlob.Length;
        }

        /// <summary>
        /// Writes a binary blob to the byte array.
        /// </summary>
        /// <param name="byteBlob"></param>
        internal void WriteByteBlob(byte[] byteBlob, int blobIndex, int length)
        {
            System.Array.Copy(byteBlob, blobIndex, Array, Index, length);
            Index += length - blobIndex;
        }

        /// <summary>
        /// Writes a binary blob to the byte array.
        /// </summary>
        /// <param name="byteBlob"></param>
        internal void WriteByteBlob(ArraySegment<byte> byteBlob)
        {
            System.Array.Copy(byteBlob.Array, byteBlob.Offset, Array, Index, byteBlob.Count);
            Index += byteBlob.Count;
        }

        /// <summary>
        /// Writes a UTF8 string to the byte array.
        /// </summary>
        /// <param name="utf8String"></param>
        internal void WriteString(string utf8String)
        {
            if(utf8String == null)
            {
                WriteUint(0);
            }
            var totalBytes = Encoding.UTF8.GetBytes(utf8String, 0, utf8String.Length, Array, Index + 4);
            WriteUint((uint)totalBytes);
            Index += totalBytes;
        }

        /// <summary>
        /// Writes an ASCII string to the byte array.
        /// </summary>
        /// <param name="asciiString"></param>
        internal int WriteAsciiString(string asciiString)
        {
            if (asciiString == null)
            {
                WriteUint(0);
            }
            var totalBytes = Encoding.ASCII.GetBytes(asciiString, 0, asciiString.Length, Array, Index + 4);
            WriteUint((uint)totalBytes);
            Index += totalBytes;
            return Index;
        }

        /// <summary>
        /// Writes a BigInteger to the byte array.
        /// </summary>
        /// <param name="bigInt"></param>
        internal int WriteBigInteger(BigInt bigInt)
        {
            WriteUint((uint)bigInt.Length);

            // Write to buffer backwards
            for (var i = 0; i != bigInt.Length; i++)
            {
                Array[Index + i] = bigInt.Buffer[bigInt.Length - i - 1];
            }

            Index += bigInt.Length;
            return Index;
        }

        /// <summary>
        /// Writes a NameList to the byte array.
        /// </summary>
        /// <param name="nameList"></param>
        internal int WriteNameList(NameList nameList)
        {
            if (nameList.IsEmpty)
            {
                WriteUint(0);
                return Index;
            }

            WriteAsciiString(nameList.AsString);
            return Index;
        }
    }
}
