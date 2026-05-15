using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_OPEN_FAILURE.
/// Description and Language are lazy — no allocation unless ToString() is called.
/// </summary>
internal readonly ref struct ChannelOpenFailureView
{
    public readonly uint RecipientChannel;
    public readonly uint ReasonCode;
    public readonly SshUtf8String Description;
    public readonly SshAsciiString Language;

    public ChannelOpenFailureView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
        ReasonCode = reader.ReadUInt32();
        Description = reader.ReadSshUtf8String();
        Language = reader.ReadSshAsciiString();
    }
}
