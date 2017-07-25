namespace Surfus.Shell.Messages.Channel.Requests
{
    internal class ChannelRequestPseudoTerminal : ChannelRequest
    {
        public ChannelRequestPseudoTerminal(SshPacket packet, uint recipientChannel) : base(packet, "pty-req", recipientChannel)
        {
            TermEnvironment = packet.PayloadReader.ReadString();
            TerminalWidthCharacters = packet.PayloadReader.ReadUInt32();
            TerminalHeightRows = packet.PayloadReader.ReadUInt32();
            TerminalWidthPixels = packet.PayloadReader.ReadUInt32();
            TerminalHeightPixels = packet.PayloadReader.ReadUInt32();
            TerminalModes = packet.PayloadReader.ReadBinaryString();
        }

        public ChannelRequestPseudoTerminal(uint recipientChannel, bool wantReply, string terminalEnvironment, uint terminalCharacters, uint terminalRows) : base(recipientChannel, "pty-req", wantReply)
        {
            TermEnvironment = terminalEnvironment;
            TerminalWidthCharacters = terminalCharacters;
            TerminalHeightRows = terminalRows;
        }

        public string TermEnvironment { get; }
        public uint TerminalWidthCharacters { get; }
        public uint TerminalHeightRows { get; }
        public uint TerminalWidthPixels { get; } = 640;
        public uint TerminalHeightPixels { get; } = 480;
        public byte[] TerminalModes { get; } = {};

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(TermEnvironment.GetStringSize() + 16 + TerminalModes.GetBinaryStringSize());
            writer.WriteString(TermEnvironment);
            writer.WriteUint(TerminalWidthCharacters);
            writer.WriteUint(TerminalHeightRows);
            writer.WriteUint(TerminalWidthPixels);
            writer.WriteUint(TerminalHeightPixels);
            writer.WriteBinaryString(TerminalModes);
            return writer;
        }
    }
}
