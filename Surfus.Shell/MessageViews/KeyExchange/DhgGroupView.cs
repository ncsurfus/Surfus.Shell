using System;
using System.Numerics;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.KeyExchange;

/// <summary>
/// Zero-copy view of the DH group exchange group message (SSH_MSG_KEX_DH_GEX_GROUP / type 31).
/// </summary>
internal readonly ref struct DhgGroupView
{
    public readonly ReadOnlySpan<byte> PBytes;
    public readonly ReadOnlySpan<byte> GBytes;

    public DhgGroupView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        PBytes = reader.ReadBinaryString();
        GBytes = reader.ReadBinaryString();
    }

    /// <summary>Parses P as a BigInteger. Allocates.</summary>
    public BigInteger P => new(PBytes, isUnsigned: false, isBigEndian: true);

    /// <summary>Parses G as a BigInteger. Allocates.</summary>
    public BigInteger G => new(GBytes, isUnsigned: false, isBigEndian: true);
}
