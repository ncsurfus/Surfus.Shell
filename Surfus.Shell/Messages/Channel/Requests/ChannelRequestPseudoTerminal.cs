using System;

namespace Surfus.Shell.Messages.Channel.Requests
{
    public record ChannelRequestPseudoTerminal : ChannelRequest
    {
        public ChannelRequestPseudoTerminal(SshPacket packet, uint recipientChannel)
            : base(packet, "pty-req", recipientChannel)
        {
            TermEnvironment = packet.Reader.ReadString();
            TerminalWidthCharacters = packet.Reader.ReadUInt32();
            TerminalHeightRows = packet.Reader.ReadUInt32();
            TerminalWidthPixels = packet.Reader.ReadUInt32();
            TerminalHeightPixels = packet.Reader.ReadUInt32();
            TerminalModes = packet.Reader.ReadBinaryString();
        }

        public ChannelRequestPseudoTerminal(
            uint recipientChannel,
            bool wantReply,
            string terminalEnvironment,
            uint terminalCharacters,
            uint terminalRows
        )
            : base(recipientChannel, "pty-req", wantReply)
        {
            TermEnvironment = terminalEnvironment;
            TerminalWidthCharacters = terminalCharacters;
            TerminalHeightRows = terminalRows;
        }

        public ChannelRequestPseudoTerminal(
            uint recipientChannel,
            bool wantReply,
            string terminalEnvironment,
            uint terminalCharacters,
            uint terminalRows,
            uint terminalWidthPixels,
            uint terminalHeightPixels
        )
            : base(recipientChannel, "pty-req", wantReply)
        {
            TermEnvironment = terminalEnvironment;
            TerminalWidthCharacters = terminalCharacters;
            TerminalHeightRows = terminalRows;
            TerminalWidthPixels = terminalWidthPixels;
            TerminalHeightPixels = terminalHeightPixels;
        }

        public string TermEnvironment { get; }
        public uint TerminalWidthCharacters { get; }
        public uint TerminalHeightRows { get; }
        public uint TerminalWidthPixels { get; }
        public uint TerminalHeightPixels { get; }
        public ReadOnlyMemory<byte> TerminalModes { get; } = ReadOnlyMemory<byte>.Empty;

        public override int GetPayloadSize() => base.GetPayloadSize() + TermEnvironment.GetStringSize() + 16 + TerminalModes.GetBinaryStringSize();

        public override void WritePayload(ref SpanWriter writer)
        {
            base.WritePayload(ref writer);
            writer.WriteString(TermEnvironment);
            writer.WriteUInt32(TerminalWidthCharacters);
            writer.WriteUInt32(TerminalHeightRows);
            writer.WriteUInt32(TerminalWidthPixels);
            writer.WriteUInt32(TerminalHeightPixels);
            writer.WriteBinaryString(TerminalModes);
        }
    }
}
