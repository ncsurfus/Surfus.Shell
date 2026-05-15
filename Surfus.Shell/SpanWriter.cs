using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Surfus.Shell;

/// <summary>
/// A stack-only writer for constructing SSH messages directly into a buffer without allocation.
/// </summary>
public ref struct SpanWriter
{
    private readonly Span<byte> _buffer;
    private int _position;

    public SpanWriter(Span<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    public readonly int Position => _position;

    public void WriteByte(byte value)
    {
        _buffer[_position++] = value;
    }

    public void WriteUInt32(uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.Slice(_position), value);
        _position += 4;
    }

    public void WriteBinaryString(ReadOnlySpan<byte> data)
    {
        WriteUInt32((uint)data.Length);
        data.CopyTo(_buffer.Slice(_position));
        _position += data.Length;
    }

    public void WriteBinaryString(ReadOnlyMemory<byte> data) => WriteBinaryString(data.Span);

    public void WriteString(string? value)
    {
        if (value == null || value.Length == 0)
        {
            WriteUInt32(0);
            return;
        }
        var byteCount = Encoding.UTF8.GetByteCount(value);
        WriteUInt32((uint)byteCount);
        Encoding.UTF8.GetBytes(value, _buffer.Slice(_position, byteCount));
        _position += byteCount;
    }

    public void WriteAsciiString(string? value)
    {
        if (value == null || value.Length == 0)
        {
            WriteUInt32(0);
            return;
        }
        var length = value.Length;
        WriteUInt32((uint)length);
        Encoding.ASCII.GetBytes(value, _buffer.Slice(_position, length));
        _position += length;
    }

    public void WriteBytes(ReadOnlySpan<byte> data)
    {
        data.CopyTo(_buffer.Slice(_position));
        _position += data.Length;
    }

    public void WriteRandom(int count)
    {
        RandomNumberGenerator.Fill(_buffer.Slice(_position, count));
        _position += count;
    }

    public readonly Span<byte> Written => _buffer.Slice(0, _position);
    public readonly Span<byte> Remaining => _buffer.Slice(_position);
}
