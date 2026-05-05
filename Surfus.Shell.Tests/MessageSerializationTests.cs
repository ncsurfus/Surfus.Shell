using Surfus.Shell;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Tests;

public class MessageSerializationTests
{
    [Fact]
    public void ServiceRequest_WritesCorrectMessageType()
    {
        var msg = new ServiceRequest("ssh-userauth");
        var writer = msg.GetByteWriter();

        Assert.Equal((byte)MessageType.SSH_MSG_SERVICE_REQUEST, writer.Bytes[SshPacket.DataIndex]);
    }

    [Fact]
    public void ServiceRequest_WritesServiceName()
    {
        var msg = new ServiceRequest("ssh-userauth");
        var writer = msg.GetByteWriter();

        // Read back: skip to after message type byte
        var reader = new ByteReader(((ReadOnlyMemory<byte>)writer.Bytes).Slice(SshPacket.DataIndex + 1));
        Assert.Equal("ssh-userauth", reader.ReadString());
    }

    [Fact]
    public void Ignore_RoundTrip()
    {
        var original = new Ignore("test data");
        var writer = original.GetByteWriter();

        // Build a read packet from the writer's buffer
        var packet = MakeReadPacket(writer);
        var parsed = new Ignore(packet);
        Assert.Equal("test data", parsed.Data);
    }

    [Fact]
    public void Disconnect_RoundTrip()
    {
        var original = new Disconnect(Disconnect.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, "goodbye", "en");
        var writer = original.GetByteWriter();

        var packet = MakeReadPacket(writer);
        var parsed = new Disconnect(packet);
        Assert.Equal(Disconnect.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, parsed.Reason);
        Assert.Equal("goodbye", parsed.Description);
        Assert.Equal("en", parsed.LanguageTag);
    }

    [Fact]
    public void Disconnect_NullLanguageTag()
    {
        var original = new Disconnect(Disconnect.DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, "error");
        var writer = original.GetByteWriter();

        var packet = MakeReadPacket(writer);
        var parsed = new Disconnect(packet);
        Assert.Equal("error", parsed.Description);
        Assert.Null(parsed.LanguageTag);
    }

    [Fact]
    public void KexInit_RoundTrip()
    {
        var original = new Messages.KeyExchange.KexInit(new SshAlgorithms());
        var bytes = original.Bytes;

        // Build a packet buffer: [0..3]=packetSize, [4]=paddingLen, [5..]=payload
        var buffer = new byte[5 + bytes.Length];
        buffer[4] = 0;
        bytes.Span.CopyTo(buffer.AsSpan(5));

        var packet = new SshPacket(buffer, packetStart: 0, packetLength: 5 + bytes.Length);
        packet.Reader.ReadByte(); // consume message type

        var parsed = new Messages.KeyExchange.KexInit(packet);

        Assert.Equal(original.KexAlgorithms.AsString, parsed.KexAlgorithms.AsString);
        Assert.Equal(original.EncryptionClientToServer.AsString, parsed.EncryptionClientToServer.AsString);
        Assert.Equal(original.MacClientToServer.AsString, parsed.MacClientToServer.AsString);
        Assert.Equal(original.CompressionClientToServer.AsString, parsed.CompressionClientToServer.AsString);
    }

    [Fact]
    public void MessageEvent_ParsesType()
    {
        var original = new Ignore("test");
        var writer = original.GetByteWriter();

        // MessageEvent expects to read the type byte itself, so build packet at DataIndex
        var packet = new SshPacket(writer.Bytes, packetStart: SshPacket.PacketSizeIndex, packetLength: writer.DataLength + 5);
        var messageEvent = new MessageEvent(packet);

        Assert.Equal(MessageType.SSH_MSG_IGNORE, messageEvent.Type);
        Assert.Equal((byte)MessageType.SSH_MSG_IGNORE, messageEvent.TypeId);
    }

    /// <summary>
    /// Creates a read-oriented SshPacket from a ByteWriter, positioned after the message type byte.
    /// This simulates how incoming packets are parsed: the MessageEvent reads the type byte,
    /// then the message constructor reads the remaining fields.
    /// </summary>
    private static SshPacket MakeReadPacket(ByteWriter writer)
    {
        // The writer buffer layout: [0..3]=seq, [4..7]=packetSize, [8]=paddingLen, [9]=msgType, [10..]=data
        // For reading, we create a packet starting at PacketSizeIndex (4) so the reader starts at index 5 (after packet header)
        // But we need the reader to start after the message type byte (index 10 = DataIndex + 1)
        var packet = new SshPacket(writer.Bytes, packetStart: SshPacket.PacketSizeIndex, packetLength: writer.DataLength + 5);
        packet.Reader.ReadByte(); // consume message type byte
        return packet;
    }
}
