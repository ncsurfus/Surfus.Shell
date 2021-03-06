namespace Surfus.Shell.Messages.Channel
{
    public class ChannelWindowAdjust : IClientMessage, IChannelRecipient
    {
        public ChannelWindowAdjust(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            BytesToAdd = packet.Reader.ReadUInt32();
        }

        public ChannelWindowAdjust(uint recipientChannel, uint bytesToAdd)
        {
            RecipientChannel = recipientChannel;
            BytesToAdd = bytesToAdd;
        }

        public uint BytesToAdd { get; }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, 8);
            writer.WriteUint(RecipientChannel);
            writer.WriteUint(BytesToAdd);
            return writer;
        }
    }
}
