using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews;

/// <summary>
/// Zero-copy view of SSH_MSG_IGNORE.
/// </summary>
internal readonly ref struct IgnoreView
{
    public readonly ReadOnlySpan<byte> Data;

    public IgnoreView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        Data = reader.ReadBinaryString();
    }
}
