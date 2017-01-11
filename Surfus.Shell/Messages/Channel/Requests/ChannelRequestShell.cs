namespace Surfus.Shell.Messages.Channel.Requests
{
    public class ChannelRequestShell : ChannelRequest
    {
        public ChannelRequestShell(byte[] buffer) : base(buffer)
        {

        }

        public ChannelRequestShell(uint recipientChannel, bool wantReply) : base(recipientChannel, "shell", wantReply)
        {

        }
    }
}
