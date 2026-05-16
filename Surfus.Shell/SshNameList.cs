using System;
using System.Text;

namespace Surfus.Shell;

/// <summary>
/// A non-allocating view of an SSH name-list (comma-separated ASCII identifiers).
/// Call ToStringArray() only when you need heap-allocated strings.
/// </summary>
internal readonly ref struct SshNameList
{
    public readonly ReadOnlySpan<byte> Bytes;

    public SshNameList(ReadOnlySpan<byte> bytes) => Bytes = bytes;

    public int Length => Bytes.Length;
    public bool IsEmpty => Bytes.Length == 0;

    /// <summary>
    /// Checks if the name-list contains the given name. Zero-allocation.
    /// Usage: list.Contains("aes256-gcm@openssh.com"u8)
    /// </summary>
    public bool Contains(ReadOnlySpan<byte> name)
    {
        var remaining = Bytes;
        while (remaining.Length > 0)
        {
            var comma = remaining.IndexOf((byte)',');
            var entry = comma >= 0 ? remaining.Slice(0, comma) : remaining;
            if (entry.SequenceEqual(name)) return true;
            remaining = comma >= 0 ? remaining.Slice(comma + 1) : default;
        }
        return false;
    }

    /// <summary>
    /// Returns the first name in the list that matches any of the candidates (in candidate order).
    /// Returns null if no match. Allocates the matched string.
    /// </summary>
    public string? FirstMatch(ReadOnlySpan<byte> candidates)
    {
        var candidateList = new SshNameList(candidates);
        var remaining = candidateList.Bytes;
        while (remaining.Length > 0)
        {
            var comma = remaining.IndexOf((byte)',');
            var candidate = comma >= 0 ? remaining.Slice(0, comma) : remaining;
            if (Contains(candidate))
                return Encoding.ASCII.GetString(candidate);
            remaining = comma >= 0 ? remaining.Slice(comma + 1) : default;
        }
        return null;
    }

    /// <summary>
    /// Allocates a string array of all names. Use sparingly.
    /// </summary>
    public string[] ToStringArray()
    {
        if (Bytes.Length == 0) return Array.Empty<string>();
        var str = Encoding.ASCII.GetString(Bytes);
        return str.Split(',');
    }

    public override string ToString() => Encoding.ASCII.GetString(Bytes);
}
