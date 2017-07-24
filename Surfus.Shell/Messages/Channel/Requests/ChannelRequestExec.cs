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

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(Command.GetStringSize());
            writer.WriteString(Command);
            return writer;
        }
    }
}
