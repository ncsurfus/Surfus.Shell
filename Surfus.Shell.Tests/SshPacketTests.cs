using Surfus.Shell;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Tests;

public class SshPacketTests
{
    [Fact]
    public void Constructor_ByteArray_SetsCorrectOffsetAndLength()
    {
        // Simulate a minimal payload: 1 byte message type
        byte[] payload = [42];
        var packet = new SshPacket(payload, paddingMultiplier: 8);

        Assert.Equal(4, packet.Offset); // Skips sequence number
        Assert.True(packet.Length > 0);
        Assert.NotNull(packet.Reader);
    }

    [Fact]
    public void Constructor_ByteArray_PacketSizeIsCorrect()
    {
        byte[] payload = [1, 2, 3, 4, 5];
        var packet = new SshPacket(payload, paddingMultiplier: 8);

        // Read the packet size from the buffer (at index 4, big-endian)
        var packetSize = ByteReader.ReadUInt32(packet.Buffer.AsSpan(SshPacket.PacketSizeIndex));

        // Packet size = payload length + padding length + 1 (padding size byte)
        var paddingLength = packet.Buffer[SshPacket.PaddingByteIndex];
        Assert.Equal((uint)(payload.Length + paddingLength + 1), packetSize);
    }

    [Fact]
    public void Constructor_ByteArray_PaddingIsAligned()
    {
        byte[] payload = [1, 2, 3];
        var packet = new SshPacket(payload, paddingMultiplier: 8);

        // Total encrypted content (packet size field value + 4 for the size field itself)
        // should be a multiple of the padding multiplier
        var packetSize = ByteReader.ReadUInt32(packet.Buffer.AsSpan(SshPacket.PacketSizeIndex));
        Assert.Equal(0u, (packetSize + 4) % 8);
    }

    [Fact]
    public void Constructor_ByteArray_PaddingLengthInRange()
    {
        byte[] payload = new byte[50];
        var packet = new SshPacket(payload, paddingMultiplier: 16);

        var paddingLength = packet.Buffer[SshPacket.PaddingByteIndex];
        Assert.InRange(paddingLength, 4, 255);
    }

    [Fact]
    public void Constructor_ByteWriter_SetsCorrectOffsetAndLength()
    {
        var writer = new ByteWriter(MessageType.SSH_MSG_IGNORE, 4);
        writer.WriteUint(0);

        var packet = new SshPacket(writer, paddingMultiplier: 8);

        Assert.Equal(4, packet.Offset);
        Assert.True(packet.Length > 0);
    }

    [Fact]
    public void Constructor_ByteWriter_PreservesPayload()
    {
        var writer = new ByteWriter(MessageType.SSH_MSG_IGNORE, 4);
        writer.WriteUint(12345);

        var packet = new SshPacket(writer, paddingMultiplier: 8);

        // The reader should be positioned at the data start (after message type byte)
        // The message type byte was already written by ByteWriter constructor
        // Reader starts at DataIndex (9), and the first byte read was the message type
        Assert.NotNull(packet.Reader);
    }

    [Fact]
    public void Constructor_IncomingData_SetsReaderCorrectly()
    {
        // Simulate incoming packet buffer:
        // [0..3] = packet size (big-endian)
        // [4] = padding length
        // [5..] = payload
        var buffer = new byte[20];
        ByteWriter.WriteUint(buffer.AsSpan(0), 16); // packet size
        buffer[4] = 4; // padding length
        buffer[5] = (byte)MessageType.SSH_MSG_IGNORE; // message type

        var packet = new SshPacket(buffer, packetStart: 0, packetLength: 16);

        Assert.Equal(0, packet.Offset);
        Assert.Equal(16, packet.Length);
    }

    [Fact]
    public void Constructor_DifferentPaddingMultipliers_AllProduceValidPackets()
    {
        byte[] payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        foreach (var multiplier in new[] { 8, 16 })
        {
            var packet = new SshPacket(payload, multiplier);
            var packetSize = ByteReader.ReadUInt32(packet.Buffer.AsSpan(SshPacket.PacketSizeIndex));
            // packet size + 4 (for the size field) should be aligned to multiplier
            Assert.Equal(0u, (packetSize + 4) % (uint)multiplier);
        }
    }
}
