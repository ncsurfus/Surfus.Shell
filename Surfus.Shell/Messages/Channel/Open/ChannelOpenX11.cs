namespace Surfus.Shell.Messages.Channel.Open
{
    internal class ChannelOpenX11 : ChannelOpen
    {
        public ChannelOpenX11(SshPacket packet) : base(packet, "x11")
        {
            OriginatorAddress = packet.PayloadReader.ReadString();
            OriginatorPort = packet.PayloadReader.ReadUInt32();
        }

        public ChannelOpenX11(string originatorAddress, uint originatorPort, uint senderChannel) : base("x11", senderChannel)
        {
            OriginatorAddress = originatorAddress;
            OriginatorPort = originatorPort;
        }

        public string OriginatorAddress { get; }
        public uint OriginatorPort { get; }

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(OriginatorAddress.GetStringSize() + 4);
            writer.WriteString(OriginatorAddress);
            writer.WriteUint(OriginatorPort);
            return writer;
        }

        public override void WriteMessage(SshPacketByteWriter writer)
        {
            base.WriteMessage(writer);
            writer.WriteString(OriginatorAddress);
            writer.WriteUint(OriginatorPort);
        }
    }
}
