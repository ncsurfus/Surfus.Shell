namespace Surfus.Shell.Messages.Channel
{
    internal record ChannelFailure : IClientMessage, IChannelRecipient
    {
        public ChannelFailure(uint recipientChannel)
        {
            RecipientChannel = recipientChannel;
        }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_FAILURE;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => 4;

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteUInt32(RecipientChannel);
        }
    }
}
