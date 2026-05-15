using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_EOF.
/// </summary>
internal readonly ref struct ChannelEofView
{
    public readonly uint RecipientChannel;

    public ChannelEofView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
    }
}
