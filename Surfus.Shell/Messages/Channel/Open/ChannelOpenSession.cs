namespace Surfus.Shell.Messages.Channel.Open
{
    public class ChannelOpenSession : ChannelOpen
    {
        public ChannelOpenSession(byte[] buffer) : base(buffer)
        {

        }

        public ChannelOpenSession(uint senderChannel, uint initialWindowSize = 35000) : base("session", senderChannel, initialWindowSize)
        {

        }
    }
}
