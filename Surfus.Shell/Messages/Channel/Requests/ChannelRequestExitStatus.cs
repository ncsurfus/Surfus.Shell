using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Requests
{
    internal class ChannelRequestExitStatus : ChannelRequest
    {
        public ChannelRequestExitStatus(SshPacket packet, uint recipientChannel) : base(packet, "exec", recipientChannel)
        {
            ExitStatus = packet.Reader.ReadUInt32();
        }

        public ChannelRequestExitStatus(uint recipientChannel, bool wantReply, uint exitStatus) : base(recipientChannel, "exec", wantReply)
        {
            ExitStatus = exitStatus;
        }

        public uint ExitStatus { get; }

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(4);
            writer.WriteUint(ExitStatus);
            return writer;
        }
    }
}
