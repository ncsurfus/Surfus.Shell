using System;
using System.Buffers.Binary;
using Surfus.Shell;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Tests;

/// <summary>
/// Helpers for constructing MessageEvents in tests.
/// </summary>
internal static class TestMessageFactory
{
    /// <summary>
    /// Creates a MessageEvent containing SSH_MSG_CHANNEL_DATA with the given payload.
    /// </summary>
    internal static MessageEvent CreateChannelData(ReadOnlySpan<byte> data, uint recipientChannel = 0)
    {
        // Layout: [4 seq][4 pktlen][1 padlen][1 type][4 recipient][4 datalen][data]
        var totalLen = 4 + 4 + 1 + 1 + 4 + 4 + data.Length;
        var buf = new byte[totalLen];
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(4), (uint)(1 + 1 + 4 + 4 + data.Length));
        buf[8] = 0; // padding_length
        buf[9] = (byte)MessageType.SSH_MSG_CHANNEL_DATA;
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(10), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(14), (uint)data.Length);
        data.CopyTo(buf.AsSpan(18));

        var packet = new SshPacket(buf, packetStart: 4, packetLength: totalLen - 4);
        return new MessageEvent(packet);
    }
}
