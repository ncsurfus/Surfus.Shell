using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_OPEN_CONFIRMATION.
/// </summary>
internal readonly ref struct ChannelOpenConfirmationView
{
    public readonly uint RecipientChannel;
    public readonly uint SenderChannel;
    public readonly uint InitialWindowSize;
    public readonly uint MaximumPacketSize;

    public ChannelOpenConfirmationView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
        SenderChannel = reader.ReadUInt32();
        InitialWindowSize = reader.ReadUInt32();
        MaximumPacketSize = reader.ReadUInt32();
    }
}
