using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews;

/// <summary>
/// Zero-copy view of SSH_MSG_DISCONNECT.
/// </summary>
internal readonly ref struct DisconnectView
{
    public readonly uint ReasonCode;
    public readonly SshUtf8String Description;
    public readonly SshAsciiString LanguageTag;

    public DisconnectView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        ReasonCode = reader.ReadUInt32();
        Description = reader.ReadSshUtf8String();
        LanguageTag = reader.ReadSshAsciiString();
    }
}
