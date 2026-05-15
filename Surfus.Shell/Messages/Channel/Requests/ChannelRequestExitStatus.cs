namespace Surfus.Shell.Messages.Channel.Requests
{
    internal record ChannelRequestExitStatus : ChannelRequest
    {
        public ChannelRequestExitStatus(SshPacket packet, uint recipientChannel)
            : base(packet, "exit-status", recipientChannel)
        {
            ExitStatus = packet.Reader.ReadUInt32();
        }

        public ChannelRequestExitStatus(uint recipientChannel, bool wantReply, uint exitStatus)
            : base(recipientChannel, "exit-status", wantReply)
        {
            ExitStatus = exitStatus;
        }

        public uint ExitStatus { get; }

        public override int GetPayloadSize() => base.GetPayloadSize() + 4;

        public override void WritePayload(ref SpanWriter writer)
        {
            base.WritePayload(ref writer);
            writer.WriteUInt32(ExitStatus);
        }
    }
}
