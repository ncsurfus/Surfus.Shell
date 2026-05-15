using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews;

/// <summary>
/// Zero-copy view of SSH_MSG_SERVICE_ACCEPT.
/// </summary>
internal readonly ref struct ServiceAcceptView
{
    public readonly SshAsciiString ServiceName;

    public ServiceAcceptView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        ServiceName = reader.ReadSshAsciiString();
    }
}
