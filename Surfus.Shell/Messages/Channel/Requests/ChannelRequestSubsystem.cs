using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Requests
{
    public class ChannelRequestSubsystem : ChannelRequest
    {
        public ChannelRequestSubsystem(byte[] buffer) : base(buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                stream.Position = BaseMemoryStreamPosition;
                Subsystem = stream.ReadString();
            }
        }

        public ChannelRequestSubsystem(uint recipientChannel, bool wantReply, string subsystem) : base(recipientChannel, "subsysem", wantReply)
        {
            Subsystem = subsystem;
        }

        public string Subsystem { get; }

        public override byte[] GetBytes()
        {
            using (var stream = GetMemoryStream())
            {
                stream.WriteString(Subsystem);
                return stream.ToArray();
            }
        }
    }
}
