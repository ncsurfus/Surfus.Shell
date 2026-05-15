using Surfus.Shell;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Tests;

public class MessageSerializationTests
{
    [Fact]
    public void ServiceRequest_WritesCorrectMessageType()
    {
        var msg = new ServiceRequest("ssh-userauth");
        Assert.Equal(MessageType.SSH_MSG_SERVICE_REQUEST, msg.Type);
    }

    [Fact]
    public void ServiceRequest_WritesServiceName()
    {
        var msg = new ServiceRequest("ssh-userauth");
        var buffer = new byte[msg.GetPayloadSize()];
        var writer = new SpanWriter(buffer);
        msg.WritePayload(ref writer);

        var reader = new ByteReader((ReadOnlyMemory<byte>)buffer);
        Assert.Equal("ssh-userauth", reader.ReadString());
    }

    [Fact]
    public void Ignore_RoundTrip()
    {
        var original = new Ignore("test data");
        var packet = MakeReadPacket(original);
        var parsed = new Ignore(packet);
        Assert.Equal("test data", parsed.Data);
    }

    [Fact]
    public void Disconnect_RoundTrip()
    {
        var original = new Disconnect(Disconnect.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, "goodbye", "en");
        var packet = MakeReadPacket(original);
        var parsed = new Disconnect(packet);
        Assert.Equal(Disconnect.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, parsed.Reason);
        Assert.Equal("goodbye", parsed.Description);
        Assert.Equal("en", parsed.LanguageTag);
    }

    [Fact]
    public void Disconnect_NullLanguageTag()
    {
        var original = new Disconnect(Disconnect.DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, "error");
        var packet = MakeReadPacket(original);
        var parsed = new Disconnect(packet);
        Assert.Equal("error", parsed.Description);
        Assert.Equal(string.Empty, parsed.LanguageTag);
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
        var payloadSize = original.GetPayloadSize();
        // Build a full packet buffer: [0..3]=seq, [4..7]=packetSize, [8]=paddingLen, [9]=msgType, [10..]=payload
        var buffer = new byte[10 + payloadSize + 255];
        buffer[SshPacket.DataIndex] = original.MessageId;
        var payloadSpan = buffer.AsSpan(SshPacket.DataIndex + 1);
        var writer = new SpanWriter(payloadSpan);
        original.WritePayload(ref writer);

        var packet = new SshPacket(buffer, packetStart: SshPacket.PacketSizeIndex, packetLength: payloadSize + 1 + 5);
        var messageEvent = new MessageEvent(packet);

        Assert.Equal(MessageType.SSH_MSG_IGNORE, messageEvent.Type);
        Assert.Equal((byte)MessageType.SSH_MSG_IGNORE, messageEvent.TypeId);
    }

    /// <summary>
    /// Creates a read-oriented SshPacket from a message, positioned after the message type byte.
    /// </summary>
    private static SshPacket MakeReadPacket(IClientMessage msg)
    {
        var payloadSize = msg.GetPayloadSize();
        // Layout: [0..3]=seq, [4..7]=packetSize, [8]=paddingLen, [9]=msgType, [10..]=payload, [padding up to 255]
        var buffer = new byte[10 + payloadSize + 255];
        buffer[SshPacket.DataIndex] = msg.MessageId;
        var payloadSpan = buffer.AsSpan(SshPacket.DataIndex + 1, payloadSize);
        var writer = new SpanWriter(payloadSpan);
        msg.WritePayload(ref writer);

        var packet = new SshPacket(buffer, packetStart: SshPacket.PacketSizeIndex, packetLength: payloadSize + 1 + 5);
        packet.Reader.ReadByte(); // consume message type byte
        return packet;
    }
}
