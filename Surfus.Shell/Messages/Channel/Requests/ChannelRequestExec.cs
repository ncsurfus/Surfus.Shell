using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Requests
{
    internal class ChannelRequestExec : ChannelRequest
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
            var writer = GetByteWriter(GetBaseSize() + Command.GetStringSize());
            writer.WriteString(Command);
            return writer.Bytes;
        }
    }
}
