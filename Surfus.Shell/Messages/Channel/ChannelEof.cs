namespace Surfus.Shell.Messages.Channel
{
    public class ChannelEof : IClientMessage, IChannelRecipient
    {
        public ChannelEof(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
        }

        public ChannelEof(uint recipientChannel)
        {
            RecipientChannel = recipientChannel;
        }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_EOF;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, 4);
            writer.WriteUint(RecipientChannel);
            return writer;
        }
    }
}
