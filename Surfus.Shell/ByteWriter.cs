using System;
using System.Collections.Generic;
using System.Text;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell
{
    public class ByteWriter
    {
        public byte[] Bytes => _bytes;

        private readonly byte[] _bytes;
        private int _position;

        public ByteWriter(int size)
        {
            _bytes = new byte[size];
        }

        public void WriteByte(byte value)
        {
            _bytes[_position++] = value;
        }

        public void WriteUint(uint value)
        {
            if (BitConverter.IsLittleEndian)
            {
                _bytes[_position++] = (byte)(value >> 24);
                _bytes[_position++] = (byte)(value >> 16);
                _bytes[_position++] = (byte)(value >> 8);
                _bytes[_position++] = (byte)value;
            }
            else
            {
                _bytes[_position++] = (byte)value;
                _bytes[_position++] = (byte)(value >> 24);
                _bytes[_position++] = (byte)(value >> 16);
                _bytes[_position++] = (byte)(value >> 8);
            }
        }

        public void WriteBinaryString(byte[] binaryString)
        {
            WriteUint((uint)binaryString.Length);
            Array.Copy(binaryString, 0, _bytes, _position, binaryString.Length);
            _position += binaryString.Length;
        }

        public void WriteByteBlob(byte[] binaryString)
        {
            Array.Copy(binaryString, 0, _bytes, _position, binaryString.Length);
            _position += binaryString.Length;
        }

        public void WriteString(string utf8String)
        {
            var totalBytes = Encoding.UTF8.GetBytes(utf8String, 0, utf8String.Length, _bytes, _position + 4);
            WriteUint((uint)totalBytes);
            _position += totalBytes;
        }

        public void WriteAsciiString(string asciiString)
        {
            var totalBytes = Encoding.ASCII.GetBytes(asciiString, 0, asciiString.Length, _bytes, _position + 4);
            WriteUint((uint)totalBytes);
            _position += totalBytes;
        }

        public void WriteKexInit(KexInit kexInit, int size)
        {
            WriteUint((uint)size);
            kexInit.WriteBytes(this);
        }

        public void WriteBigInteger(byte[] bigInteger)
        {
            WriteUint((uint)bigInteger.Length);

            // Write to buffer backwards
            for (var i = 0; i != bigInteger.Length; i++)
            {
                _bytes[_position + i] = bigInteger[bigInteger.Length - i - 1];
            }

            _position += bigInteger.Length;
        }

        public void WriteNameList(NameList nameList)
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
