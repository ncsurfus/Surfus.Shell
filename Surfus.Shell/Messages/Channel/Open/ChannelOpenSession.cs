namespace Surfus.Shell.Messages.Channel.Open
{
    public record ChannelOpenSession : ChannelOpen
    {
        public ChannelOpenSession(uint senderChannel, uint initialWindowSize = 35000) : base("session", senderChannel, initialWindowSize) { }
    }
}
