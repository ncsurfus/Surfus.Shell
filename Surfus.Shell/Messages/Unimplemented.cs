namespace Surfus.Shell.Messages
{
    internal record Unimplemented : IClientMessage
    {
        public Unimplemented(uint packetSequenceNumber)
        {
            PacketSequenceNumber = packetSequenceNumber;
        }

        public uint PacketSequenceNumber { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_UNIMPLEMENTED;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => 4;

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteUInt32(PacketSequenceNumber);
        }
    }
}
