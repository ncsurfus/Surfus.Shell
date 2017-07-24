namespace Surfus.Shell.Messages.Channel
{
    public class ChannelOpenConfirmation : IMessage, IChannelRecipient
    {
        public ChannelOpenConfirmation(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            SenderChannel = packet.Reader.ReadUInt32();
            InitialWindowSize = packet.Reader.ReadUInt32();
            MaximumWindowSize = packet.Reader.ReadUInt32();
        }

        public uint RecipientChannel { get; }
        public uint SenderChannel { get; }
        public uint InitialWindowSize { get; } = 1024;
        public uint MaximumWindowSize { get; } = 32000;

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
        public byte MessageId => (byte)Type;
    }
}
