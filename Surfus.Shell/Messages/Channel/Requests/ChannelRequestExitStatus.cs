namespace Surfus.Shell.Messages.Channel.Requests
{
    internal class ChannelRequestExitStatus : ChannelRequest
    {
        public ChannelRequestExitStatus(SshPacket packet, uint recipientChannel) : base(packet, "exec", recipientChannel)
        {
            ExitStatus = packet.PayloadReader.ReadUInt32();
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

        public override void WriteMessage(SshPacketByteWriter writer)
        {
            base.WriteMessage(writer);
            writer.WriteUint(ExitStatus);
        }
    }
}
