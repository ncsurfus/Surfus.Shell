namespace Surfus.Shell.Messages.Channel
{
    internal record ChannelEof : IClientMessage, IChannelRecipient
    {
        public ChannelEof(uint recipientChannel)
        {
            RecipientChannel = recipientChannel;
        }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_EOF;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => 4;

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteUInt32(RecipientChannel);
        }
    }
}
