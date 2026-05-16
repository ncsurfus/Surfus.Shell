using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.KeyExchange;

/// <summary>
/// Zero-copy view of SSH_MSG_KEXINIT for parsing the server's key exchange init.
/// </summary>
internal readonly ref struct KexInitView
{
    public readonly ReadOnlySpan<byte> Cookie;
    public readonly SshNameList KexAlgorithms;
    public readonly SshNameList ServerHostKeyAlgorithms;
    public readonly SshNameList EncryptionClientToServer;
    public readonly SshNameList EncryptionServerToClient;
    public readonly SshNameList MacClientToServer;
    public readonly SshNameList MacServerToClient;
    public readonly SshNameList CompressionClientToServer;
    public readonly SshNameList CompressionServerToClient;
    public readonly SshNameList LanguagesClientToServer;
    public readonly SshNameList LanguagesServerToClient;
    public readonly bool FirstKexPacketFollows;

    public KexInitView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        Cookie = reader.ReadBytes(16);
        KexAlgorithms = reader.ReadNameList();
        ServerHostKeyAlgorithms = reader.ReadNameList();
        EncryptionClientToServer = reader.ReadNameList();
        EncryptionServerToClient = reader.ReadNameList();
        MacClientToServer = reader.ReadNameList();
        MacServerToClient = reader.ReadNameList();
        CompressionClientToServer = reader.ReadNameList();
        CompressionServerToClient = reader.ReadNameList();
        LanguagesClientToServer = reader.ReadNameList();
        LanguagesServerToClient = reader.ReadNameList();
        FirstKexPacketFollows = reader.ReadByte() != 0;
        // Reserved uint32
        reader.ReadUInt32();
        BytesConsumed = payload.Length - reader.Remaining;
    }

    /// <summary>Total bytes consumed from the payload (for raw bytes capture).</summary>
    public readonly int BytesConsumed;
}
