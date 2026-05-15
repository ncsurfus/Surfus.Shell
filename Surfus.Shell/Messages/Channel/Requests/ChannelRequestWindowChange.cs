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

        public override int GetPayloadSize() => base.GetPayloadSize() + 16;

        public override void WritePayload(ref SpanWriter writer)
        {
            base.WritePayload(ref writer);
            writer.WriteUInt32(TerminalWidthCharacters);
            writer.WriteUInt32(TerminalHeightRows);
            writer.WriteUInt32(TerminalWidthPixels);
            writer.WriteUInt32(TerminalHeightPixels);
        }
    }
}
