namespace Surfus.Shell.Messages.Channel.Open
{
    internal class ChannelOpenDirectTcpIp : ChannelOpen
    {
        internal ChannelOpenDirectTcpIp(SshPacket packet) : base(packet, "direct-tcpip")
        {
            Host = packet.Reader.ReadString();
            Port = packet.Reader.ReadUInt32();
            OriginatorAddress = packet.Reader.ReadString();
            OriginatorPort = packet.Reader.ReadUInt32();
        }

        public ChannelOpenDirectTcpIp(string host, uint port, string originatorAddress, uint originatorPort, uint senderChannel) : base("direct-tcpip", senderChannel)
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

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(Host.GetStringSize() + 4 + OriginatorAddress.GetStringSize() + 4);
            writer.WriteString(Host);
            writer.WriteUint(Port);
            writer.WriteString(OriginatorAddress);
            writer.WriteUint(OriginatorPort);
            return writer;
        }
    }
}
