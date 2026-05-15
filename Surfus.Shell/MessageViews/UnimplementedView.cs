using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews;

/// <summary>
/// Zero-copy view of SSH_MSG_UNIMPLEMENTED.
/// </summary>
internal readonly ref struct UnimplementedView
{
    public readonly uint PacketSequenceNumber;

    public UnimplementedView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        PacketSequenceNumber = reader.ReadUInt32();
    }
}
