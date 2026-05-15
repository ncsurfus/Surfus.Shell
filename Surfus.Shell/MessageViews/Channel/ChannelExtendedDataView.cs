using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_EXTENDED_DATA. Only valid on the stack while the packet buffer is alive.
/// </summary>
internal readonly ref struct ChannelExtendedDataView
{
    public readonly uint RecipientChannel;
    public readonly uint DataTypeCode;
    public readonly ReadOnlySpan<byte> Data;

    public ChannelExtendedDataView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
        DataTypeCode = reader.ReadUInt32();
        Data = reader.ReadBinaryString();
    }
}
