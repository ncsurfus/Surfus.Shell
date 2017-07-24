namespace Surfus.Shell.Messages.Channel.Requests
{
    internal class ChannelRequestSubsystem : ChannelRequest
    {
        public ChannelRequestSubsystem(SshPacket packet, uint recipientChannel) : base(packet, "subsystem", recipientChannel)
        {
            Subsystem = packet.Reader.ReadString();
        }

        public ChannelRequestSubsystem(uint recipientChannel, bool wantReply, string subsystem) : base(recipientChannel, "subsysem", wantReply)
        {
            Subsystem = subsystem;
        }

        public string Subsystem { get; }

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(Subsystem.GetStringSize());
            writer.WriteString(Subsystem);
            return writer;
        }
    }
}
