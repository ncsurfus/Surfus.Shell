using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_SUCCESS.
/// </summary>
internal readonly ref struct ChannelSuccessView
{
    public readonly uint RecipientChannel;

    public ChannelSuccessView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
    }
}
