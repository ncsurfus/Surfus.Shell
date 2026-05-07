namespace Surfus.Shell.Messages.Channel.Requests
{
    internal record ChannelRequestExitStatus : ChannelRequest
    {
        public ChannelRequestExitStatus(SshPacket packet, uint recipientChannel)
            : base(packet, "exit-status", recipientChannel)
        {
            ExitStatus = packet.Reader.ReadUInt32();
        }

        public ChannelRequestExitStatus(uint recipientChannel, bool wantReply, uint exitStatus)
            : base(recipientChannel, "exit-status", wantReply)
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
