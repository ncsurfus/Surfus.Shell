using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_DATA. Only valid on the stack while the packet buffer is alive.
/// </summary>
internal readonly ref struct ChannelDataView
{
    public readonly uint RecipientChannel;
    public readonly ReadOnlySpan<byte> Data;

    public ChannelDataView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
        Data = reader.ReadBinaryString();
    }
}
