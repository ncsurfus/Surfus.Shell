using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.KeyExchange;

/// <summary>
/// Zero-copy view of the ECDH reply message (SSH_MSG_KEX_ECDH_REPLY / type 31).
/// Binary string fields are spans into the packet buffer — copy them if needed beyond this scope.
/// </summary>
internal readonly ref struct EcdhReplyView
{
    public readonly ReadOnlySpan<byte> ServerPublicHostKeyAndCertificates;
    public readonly ReadOnlySpan<byte> ServerPublicKey;
    public readonly ReadOnlySpan<byte> HSignature;

    public EcdhReplyView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        ServerPublicHostKeyAndCertificates = reader.ReadBinaryString();
        ServerPublicKey = reader.ReadBinaryString();
        HSignature = reader.ReadBinaryString();
    }
}
