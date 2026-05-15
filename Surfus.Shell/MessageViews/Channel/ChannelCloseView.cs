using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_CLOSE.
/// </summary>
internal readonly ref struct ChannelCloseView
{
    public readonly uint RecipientChannel;

    public ChannelCloseView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
    }
}
