using System;

namespace Surfus.Shell.Messages.Channel.Requests
{
    /// <summary>
    /// SSH pty-req channel request (RFC 4254 §6.2).
    /// </summary>
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
            uint terminalHeightPixels,
            ReadOnlyMemory<byte> terminalModes = default
        )
            : base(recipientChannel, "pty-req", wantReply)
        {
            TermEnvironment = terminalEnvironment;
            TerminalWidthCharacters = terminalCharacters;
            TerminalHeightRows = terminalRows;
            TerminalWidthPixels = terminalWidthPixels;
            TerminalHeightPixels = terminalHeightPixels;
            TerminalModes = terminalModes;
        }

        /// <summary>The TERM environment variable value (e.g. "xterm").</summary>
        public string TermEnvironment { get; }

        /// <summary>Terminal width in characters.</summary>
        public uint TerminalWidthCharacters { get; }

        /// <summary>Terminal height in rows.</summary>
        public uint TerminalHeightRows { get; }

        /// <summary>Terminal width in pixels (0 if unspecified).</summary>
        public uint TerminalWidthPixels { get; }

        /// <summary>Terminal height in pixels (0 if unspecified).</summary>
        public uint TerminalHeightPixels { get; }

        /// <summary>Encoded terminal modes per RFC 4254 §8.</summary>
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
