namespace Surfus.Shell.Messages.Channel
{
    public record ChannelOpen : IClientMessage
    {
        protected ChannelOpen(SshPacket packet, string channelType)
        {
            ChannelType = channelType;
            SenderChannel = packet.Reader.ReadUInt32();
            InitialWindowSize = packet.Reader.ReadUInt32();
            MaximumPacketSize = packet.Reader.ReadUInt32();
        }

        public ChannelOpen(string channelType, uint senderChannel, uint initialWindowSize = 35000)
        {
            ChannelType = channelType;
            SenderChannel = senderChannel;
            InitialWindowSize = initialWindowSize;
        }

        public string ChannelType { get; }
        public uint SenderChannel { get; init; }
        public uint InitialWindowSize { get; }
        public uint MaximumPacketSize { get; } = 32000;

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_OPEN;
        public byte MessageId => (byte)Type;

        public virtual int GetPayloadSize() => ChannelType.GetAsciiStringSize() + 12;

        public virtual void WritePayload(ref SpanWriter writer)
        {
            writer.WriteAsciiString(ChannelType);
            writer.WriteUInt32(SenderChannel);
            writer.WriteUInt32(InitialWindowSize);
            writer.WriteUInt32(MaximumPacketSize);
        }
    }
}
