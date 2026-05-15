using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.Channel;

/// <summary>
/// Zero-copy view of SSH_MSG_CHANNEL_REQUEST.
/// </summary>
internal readonly ref struct ChannelRequestView
{
    public readonly uint RecipientChannel;
    public readonly SshAsciiString RequestType;
    public readonly bool WantReply;
    public readonly ReadOnlySpan<byte> RequestData;

    public ChannelRequestView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        RecipientChannel = reader.ReadUInt32();
        RequestType = reader.ReadSshAsciiString();
        WantReply = reader.ReadByte() != 0;
        RequestData = reader.ReadBytes(reader.Remaining);
    }

    /// <summary>
    /// Parses the exit status from the request data. Only valid when RequestType is "exit-status".
    /// </summary>
    public uint ExitStatus
    {
        get
        {
            var reader = new SpanReader(RequestData);
            return reader.ReadUInt32();
        }
    }
}
