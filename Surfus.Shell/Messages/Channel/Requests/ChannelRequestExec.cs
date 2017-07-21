using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Requests
{
    public class ChannelRequestExec : ChannelRequest
    {
        public ChannelRequestExec(SshPacket packet, uint recipientChannel) : base(packet, "exec", recipientChannel)
        {
            Command = packet.Reader.ReadString();
        }

        public ChannelRequestExec(uint recipientChannel, bool wantReply, string command) : base(recipientChannel, "exec", wantReply)
        {
            Command = command;
        }

        public string Command { get; }

        public override byte[] GetBytes()
        {
            using (var stream = GetMemoryStream())
            {
                stream.WriteString(Command);
                return stream.ToArray();
            }
        }
    }
}
