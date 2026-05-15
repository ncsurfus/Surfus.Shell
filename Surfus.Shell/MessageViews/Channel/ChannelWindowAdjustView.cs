using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_WINDOW_ADJUST.
/// </summary>
internal readonly ref struct ChannelWindowAdjustView
{
    public readonly uint RecipientChannel;
    public readonly uint BytesToAdd;

    public ChannelWindowAdjustView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
        BytesToAdd = reader.ReadUInt32();
    }
}
