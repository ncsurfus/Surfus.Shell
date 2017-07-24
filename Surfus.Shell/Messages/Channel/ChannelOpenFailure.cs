namespace Surfus.Shell.Messages.Channel
{
    public class ChannelOpenFailure : IMessage, IChannelRecipient
    {
        public ChannelOpenFailure(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            ReasonCode = packet.Reader.ReadUInt32();
            Description = packet.Reader.ReadString();
            Language = packet.Reader.ReadString();
        }

        public uint RecipientChannel { get; }
        public uint ReasonCode { get; }
        public string Description { get; }
        public string Language { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE;
        public byte MessageId => (byte)Type;
    }
}
