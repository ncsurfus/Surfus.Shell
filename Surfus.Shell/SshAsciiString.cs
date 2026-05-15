using System;
using System.Text;

namespace Surfus.Shell;

/// <summary>
/// A non-allocating view of an ASCII string backed by a span of bytes.
/// Call ToString() only when you need a heap-allocated string.
/// </summary>
internal readonly ref struct SshAsciiString
{
    public readonly ReadOnlySpan<byte> Bytes;

    public SshAsciiString(ReadOnlySpan<byte> bytes) => Bytes = bytes;

    public int Length => Bytes.Length;

    public bool Equals(ReadOnlySpan<byte> other) => Bytes.SequenceEqual(other);

    /// <summary>
    /// Compares against a UTF-8 literal without allocating.
    /// Usage: str.Is("exit-status"u8)
    /// </summary>
    public bool Is(ReadOnlySpan<byte> utf8Literal) => Bytes.SequenceEqual(utf8Literal);

    public override string ToString() => Encoding.ASCII.GetString(Bytes);
}
