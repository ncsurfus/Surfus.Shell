namespace Surfus.Shell.Messages.Channel.Requests
{
    public record ChannelRequestShell : ChannelRequest
    {
        public ChannelRequestShell(SshPacket packet, uint recipientChannel)
            : base(packet, "shell", recipientChannel) { }

        public ChannelRequestShell(uint recipientChannel, bool wantReply)
            : base(recipientChannel, "shell", wantReply) { }
    }
}
