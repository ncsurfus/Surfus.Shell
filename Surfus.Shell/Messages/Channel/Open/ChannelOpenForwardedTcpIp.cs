namespace Surfus.Shell.Messages.Channel.Open
{
    internal class ChannelOpenForwardedTcpIp : ChannelOpen
    {
        public ChannelOpenForwardedTcpIp(SshPacket packet) : base(packet, "forwarded-tcpip")
        {
            AddressConnected = packet.PayloadReader.ReadString();
            PortConnected = packet.PayloadReader.ReadUInt32();
            OriginatorAddress = packet.PayloadReader.ReadString();
            OriginatorPort = packet.PayloadReader.ReadUInt32();
        }

        public ChannelOpenForwardedTcpIp(string addressConnected, uint portConnected, string originatorAddress, uint originatorPort, uint senderChannel) : base("forwarded-tcpip", senderChannel)
        {
            AddressConnected = addressConnected;
            PortConnected = portConnected;
            OriginatorAddress = originatorAddress;
            OriginatorPort = originatorPort;
        }

        public string AddressConnected { get; }
        public uint PortConnected { get; }
        public string OriginatorAddress { get; }
        public uint OriginatorPort { get; }

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(AddressConnected.GetStringSize() + 4 + OriginatorAddress.GetStringSize() + 4);
            writer.WriteString(AddressConnected);
            writer.WriteUint(PortConnected);
            writer.WriteString(OriginatorAddress);
            writer.WriteUint(OriginatorPort);
            return writer;
        }

        public override void WriteMessage(SshPacketByteWriter writer)
        {
            base.WriteMessage(writer);
            writer.WriteString(AddressConnected);
            writer.WriteUint(PortConnected);
            writer.WriteString(OriginatorAddress);
            writer.WriteUint(OriginatorPort);
        }
    }
}
