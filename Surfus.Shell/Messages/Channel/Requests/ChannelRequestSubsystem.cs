namespace Surfus.Shell.Messages.Channel.Requests
{
    public record ChannelRequestSubsystem : ChannelRequest
    {
        public ChannelRequestSubsystem(SshPacket packet, uint recipientChannel)
            : base(packet, "subsystem", recipientChannel)
        {
            Subsystem = packet.Reader.ReadString();
        }

        public ChannelRequestSubsystem(uint recipientChannel, bool wantReply, string subsystem)
            : base(recipientChannel, "subsystem", wantReply)
        {
            Subsystem = subsystem;
        }

        public string Subsystem { get; }

        public override int GetPayloadSize() => base.GetPayloadSize() + Subsystem.GetStringSize();

        public override void WritePayload(ref SpanWriter writer)
        {
            base.WritePayload(ref writer);
            writer.WriteString(Subsystem);
        }
    }
}
