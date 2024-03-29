using Surfus.Shell.Messages.Channel.Open;

namespace Surfus.Shell.Messages.Channel
{
    internal class ChannelOpen : IClientMessage
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
        public uint SenderChannel { get; }
        public uint InitialWindowSize { get; }
        public uint MaximumPacketSize { get; } = 32000;

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_OPEN;
        public byte MessageId => (byte)Type;

        public virtual ByteWriter GetByteWriter()
        {
            return GetByteWriter(0);
        }

        public static ChannelOpen FromBuffer(SshPacket packet)
        {
            var channelType = packet.Reader.ReadAsciiString();

            switch (channelType)
            {
                case "session":
                    return new ChannelOpenSession(packet);
                case "x11":
                    return new ChannelOpenX11(packet);
                case "forwarded-tcpip":
                    return new ChannelOpenForwardedTcpIp(packet);
                case "direct-tcpip":
                    return new ChannelOpenDirectTcpIp(packet);
                default:
                    return new ChannelOpen(packet, channelType);
            }
        }

        protected ByteWriter GetByteWriter(int additionalSize)
        {
            var writer = new ByteWriter(Type, 12 + ChannelType.GetAsciiStringSize() + additionalSize);
            writer.WriteAsciiString(ChannelType);
            writer.WriteUint(SenderChannel);
            writer.WriteUint(InitialWindowSize);
            writer.WriteUint(MaximumPacketSize);
            return writer;
        }
    }
}
