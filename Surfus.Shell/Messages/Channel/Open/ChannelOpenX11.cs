namespace Surfus.Shell.Messages.Channel.Open
{
    internal record ChannelOpenX11 : ChannelOpen
    {
        public ChannelOpenX11(SshPacket packet)
            : base(packet, "x11")
        {
            OriginatorAddress = packet.Reader.ReadString();
            OriginatorPort = packet.Reader.ReadUInt32();
        }

        public ChannelOpenX11(string originatorAddress, uint originatorPort, uint senderChannel)
            : base("x11", senderChannel)
        {
            OriginatorAddress = originatorAddress;
            OriginatorPort = originatorPort;
        }

        public string OriginatorAddress { get; }
        public uint OriginatorPort { get; }

        public override int GetPayloadSize() => base.GetPayloadSize() + OriginatorAddress.GetStringSize() + 4;

        public override void WritePayload(ref SpanWriter writer)
        {
            base.WritePayload(ref writer);
            writer.WriteString(OriginatorAddress);
            writer.WriteUInt32(OriginatorPort);
        }
    }
}
