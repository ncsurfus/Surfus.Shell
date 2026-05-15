namespace Surfus.Shell.Messages.Channel.Requests
{
    public record ChannelRequestExec : ChannelRequest
    {
        public ChannelRequestExec(SshPacket packet, uint recipientChannel)
            : base(packet, "exec", recipientChannel)
        {
            Command = packet.Reader.ReadString();
        }

        public ChannelRequestExec(uint recipientChannel, bool wantReply, string command)
            : base(recipientChannel, "exec", wantReply)
        {
            Command = command;
        }

        public string Command { get; }

        public override int GetPayloadSize() => base.GetPayloadSize() + Command.GetStringSize();

        public override void WritePayload(ref SpanWriter writer)
        {
            base.WritePayload(ref writer);
            writer.WriteString(Command);
        }
    }
}
