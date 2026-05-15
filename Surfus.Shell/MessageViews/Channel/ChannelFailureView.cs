using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_FAILURE.
/// </summary>
internal readonly ref struct ChannelFailureView
{
    public readonly uint RecipientChannel;

    public ChannelFailureView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
    }
}
