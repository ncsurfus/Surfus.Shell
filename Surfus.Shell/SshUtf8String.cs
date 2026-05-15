using System;
using System.Text;

namespace Surfus.Shell;

/// <summary>
/// A non-allocating view of a UTF-8 string backed by a span of bytes.
/// Call ToString() only when you need a heap-allocated string.
/// </summary>
internal readonly ref struct SshUtf8String
{
    public readonly ReadOnlySpan<byte> Bytes;

    public SshUtf8String(ReadOnlySpan<byte> bytes) => Bytes = bytes;

    public int Length => Bytes.Length;

    public bool Is(ReadOnlySpan<byte> utf8Literal) => Bytes.SequenceEqual(utf8Literal);

    public override string ToString() => Encoding.UTF8.GetString(Bytes);
}
