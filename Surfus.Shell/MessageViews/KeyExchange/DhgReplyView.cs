using System;
using System.Numerics;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.KeyExchange;

/// <summary>
/// Zero-copy view of the DH group exchange reply message (SSH_MSG_KEX_DH_GEX_REPLY / type 33).
/// </summary>
internal readonly ref struct DhgReplyView
{
    public readonly ReadOnlySpan<byte> ServerPublicHostKeyAndCertificates;
    public readonly ReadOnlySpan<byte> FBytes;
    public readonly ReadOnlySpan<byte> HSignature;

    public DhgReplyView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        ServerPublicHostKeyAndCertificates = reader.ReadBinaryString();
        FBytes = reader.ReadBinaryString();
        HSignature = reader.ReadBinaryString();
    }

    /// <summary>Parses F as a BigInteger. Allocates.</summary>
    public BigInteger F => new(FBytes, isUnsigned: false, isBigEndian: true);
}
