namespace Surfus.Shell.Messages.Channel.Open
{
    internal record ChannelOpenSession : ChannelOpen
    {
        public ChannelOpenSession(SshPacket packet)
            : base(packet, "session") { }

        public ChannelOpenSession(uint senderChannel, uint initialWindowSize = 35000)
            : base("session", senderChannel, initialWindowSize) { }
    }
}
