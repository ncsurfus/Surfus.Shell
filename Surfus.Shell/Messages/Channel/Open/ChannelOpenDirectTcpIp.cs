namespace Surfus.Shell.Messages.Channel.Open
{
    public record ChannelOpenDirectTcpIp : ChannelOpen
    {
        internal ChannelOpenDirectTcpIp(SshPacket packet)
            : base(packet, "direct-tcpip")
        {
            Host = packet.Reader.ReadString();
            Port = packet.Reader.ReadUInt32();
            OriginatorAddress = packet.Reader.ReadString();
            OriginatorPort = packet.Reader.ReadUInt32();
        }

        public ChannelOpenDirectTcpIp(string host, uint port, string originatorAddress, uint originatorPort, uint senderChannel)
            : base("direct-tcpip", senderChannel)
        {
            Host = host;
            Port = port;
            OriginatorAddress = originatorAddress;
            OriginatorPort = originatorPort;
        }

        public string Host { get; }
        public uint Port { get; }
        public string OriginatorAddress { get; }
        public uint OriginatorPort { get; }

        public override int GetPayloadSize() => base.GetPayloadSize() + Host.GetStringSize() + 4 + OriginatorAddress.GetStringSize() + 4;

        public override void WritePayload(ref SpanWriter writer)
        {
            base.WritePayload(ref writer);
            writer.WriteString(Host);
            writer.WriteUInt32(Port);
            writer.WriteString(OriginatorAddress);
            writer.WriteUInt32(OriginatorPort);
        }
    }
}
