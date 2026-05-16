using System;
using System.Buffers.Binary;
using System.Text;

namespace Surfus.Shell;

/// <summary>
/// A stack-only reader for parsing SSH message payloads without allocation.
/// </summary>
internal ref struct SpanReader
{
    private ReadOnlySpan<byte> _remaining;

    public SpanReader(ReadOnlySpan<byte> data) => _remaining = data;

    public readonly int Remaining => _remaining.Length;

    public byte ReadByte()
    {
        var value = _remaining[0];
        _remaining = _remaining.Slice(1);
        return value;
    }

    public uint ReadUInt32()
    {
        var value = BinaryPrimitives.ReadUInt32BigEndian(_remaining);
        _remaining = _remaining.Slice(4);
        return value;
    }

    public ReadOnlySpan<byte> ReadBinaryString()
    {
        var length = (int)ReadUInt32();
        var result = _remaining.Slice(0, length);
        _remaining = _remaining.Slice(length);
        return result;
    }

    public string ReadAsciiString()
    {
        var length = (int)ReadUInt32();
        var result = Encoding.ASCII.GetString(_remaining.Slice(0, length));
        _remaining = _remaining.Slice(length);
        return result;
    }

    public SshAsciiString ReadSshAsciiString()
    {
        var length = (int)ReadUInt32();
        var result = new SshAsciiString(_remaining.Slice(0, length));
        _remaining = _remaining.Slice(length);
        return result;
    }

    public string ReadUtf8String()
    {
        var length = (int)ReadUInt32();
        var result = Encoding.UTF8.GetString(_remaining.Slice(0, length));
        _remaining = _remaining.Slice(length);
        return result;
    }

    public SshUtf8String ReadSshUtf8String()
    {
        var length = (int)ReadUInt32();
        var result = new SshUtf8String(_remaining.Slice(0, length));
        _remaining = _remaining.Slice(length);
        return result;
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        var result = _remaining.Slice(0, count);
        _remaining = _remaining.Slice(count);
        return result;
    }

    public SshNameList ReadNameList()
    {
        var length = (int)ReadUInt32();
        var result = new SshNameList(_remaining.Slice(0, length));
        _remaining = _remaining.Slice(length);
        return result;
    }

    /// <summary>
    /// Reads an RSA parameter (binary string with leading zero stripped).
    /// Allocates a byte[] since RSAParameters requires owned arrays.
    /// </summary>
    public byte[] ReadRsaParameter()
    {
        var length = (int)ReadUInt32();
        var offset = _remaining[0] == 0 ? 1 : 0;
        var result = _remaining.Slice(offset, length - offset).ToArray();
        _remaining = _remaining.Slice(length);
        return result;
    }

    /// <summary>
    /// Reads a BigInteger from a binary string (SSH mpint format).
    /// </summary>
    public System.Numerics.BigInteger ReadBigInteger()
    {
        var length = (int)ReadUInt32();
        var value = new System.Numerics.BigInteger(_remaining.Slice(0, length), isUnsigned: false, isBigEndian: true);
        _remaining = _remaining.Slice(length);
        return value;
    }

    public void Skip(int count) => _remaining = _remaining.Slice(count);
}
