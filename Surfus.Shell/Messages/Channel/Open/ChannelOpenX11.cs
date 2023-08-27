namespace Surfus.Shell.Messages.Channel.Open
{
    internal class ChannelOpenX11 : ChannelOpen
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

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(OriginatorAddress.GetStringSize() + 4);
            writer.WriteString(OriginatorAddress);
            writer.WriteUint(OriginatorPort);
            return writer;
        }
    }
}
