namespace Surfus.Shell.Messages.Channel.Requests
{
    public record ChannelRequestWindowChange : ChannelRequest
    {
        public ChannelRequestWindowChange(
            uint recipientChannel,
            uint terminalWidthCharacters,
            uint terminalHeightRows,
            uint terminalWidthPixels = 0,
            uint terminalHeightPixels = 0
        )
            : base(recipientChannel, "window-change", false)
        {
            TerminalWidthCharacters = terminalWidthCharacters;
            TerminalHeightRows = terminalHeightRows;
            TerminalWidthPixels = terminalWidthPixels;
            TerminalHeightPixels = terminalHeightPixels;
        }

        public uint TerminalWidthCharacters { get; }
        public uint TerminalHeightRows { get; }
        public uint TerminalWidthPixels { get; }
        public uint TerminalHeightPixels { get; }

        public override ByteWriter GetByteWriter()
        {
            var writer = GetByteWriter(16);
            writer.WriteUint(TerminalWidthCharacters);
            writer.WriteUint(TerminalHeightRows);
            writer.WriteUint(TerminalWidthPixels);
            writer.WriteUint(TerminalHeightPixels);
            return writer;
        }
    }
}
