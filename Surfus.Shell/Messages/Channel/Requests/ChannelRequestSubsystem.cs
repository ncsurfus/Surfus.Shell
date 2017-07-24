using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Requests
{
    internal class ChannelRequestSubsystem : ChannelRequest
    {
        public ChannelRequestSubsystem(SshPacket packet, uint recipientChannel) : base(packet, "subsystem", recipientChannel)
        {
            Subsystem = packet.Reader.ReadString();
        }

        public ChannelRequestSubsystem(uint recipientChannel, bool wantReply, string subsystem) : base(recipientChannel, "subsysem", wantReply)
        {
            Subsystem = subsystem;
        }

        public string Subsystem { get; }

        public override byte[] GetBytes()
        {
            var writer = GetByteWriterBuffered(GetBaseSize() + Subsystem.GetStringSize());
            writer.WriteString(Subsystem);
            return writer.Bytes;
        }

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriterBuffered(Subsystem.GetStringSize());
            writer.WriteString(Subsystem);
            return writer;
        }
    }
}
