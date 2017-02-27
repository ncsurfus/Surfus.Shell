using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Requests
{
    public class ChannelRequestExitStatus : ChannelRequest
    {
        public ChannelRequestExitStatus(byte[] buffer) : base(buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                stream.Position = BaseMemoryStreamPosition;
                ExitStatus = stream.ReadUInt32();
            }
        }

        public ChannelRequestExitStatus(uint recipientChannel, bool wantReply, uint exitStatus) : base(recipientChannel, "exec", wantReply)
        {
            ExitStatus = exitStatus;
        }

        public uint ExitStatus { get; }

        public override byte[] GetBytes()
        {
            using (var stream = GetMemoryStream())
            {
                stream.WriteUInt(ExitStatus);
                return stream.ToArray();
            }
        }
    }
}
