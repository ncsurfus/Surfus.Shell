using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Requests
{
    public class ChannelRequestPseudoTerminal : ChannelRequest
    {
        public ChannelRequestPseudoTerminal(byte[] buffer) : base(buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                stream.Position = BaseMemoryStreamPosition;
                TermEnvironment = stream.ReadString();
                TerminalWidthCharacters = stream.ReadUInt32();
                TerminalHeightRows = stream.ReadUInt32();
                TerminalWidthPixels = stream.ReadUInt32();
                TerminalHeightPixels = stream.ReadUInt32();
                TerminalModes = stream.ReadBinaryString();
            }
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

        public override byte[] GetBytes()
        {
            using (var stream = GetMemoryStream())
            {
                stream.WriteString(TermEnvironment);
                stream.WriteUInt(TerminalWidthCharacters);
                stream.WriteUInt(TerminalHeightRows);
                stream.WriteUInt(TerminalWidthPixels);
                stream.WriteUInt(TerminalHeightPixels);
                stream.WriteBinaryString(TerminalModes);
                return stream.ToArray();
            }
        }
    }
}
