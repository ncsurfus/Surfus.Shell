namespace Surfus.Shell.Messages.Channel
{
    public class ChannelData : IClientMessage, IChannelRecipient
    {
        public ChannelData(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            Data = packet.Reader.ReadBinaryString();
        }

        public ChannelData(uint recipientChannel, byte[] data)
        {
            RecipientChannel = recipientChannel;
            Data = data;
        }

        public byte[] Data { get; }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_DATA;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, 4 + Data.GetBinaryStringSize());
            writer.WriteUint(RecipientChannel);
            writer.WriteBinaryString(Data);
            return writer;
        }
    }
}
