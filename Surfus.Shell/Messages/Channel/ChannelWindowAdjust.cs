namespace Surfus.Shell.Messages.Channel
{
    internal record ChannelWindowAdjust : IClientMessage, IChannelRecipient
    {
        public ChannelWindowAdjust(uint recipientChannel, uint bytesToAdd)
        {
            RecipientChannel = recipientChannel;
            BytesToAdd = bytesToAdd;
        }

        public uint BytesToAdd { get; }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => 8;

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteUInt32(RecipientChannel);
            writer.WriteUInt32(BytesToAdd);
        }
    }
}
