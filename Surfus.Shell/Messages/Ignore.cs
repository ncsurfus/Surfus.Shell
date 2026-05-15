namespace Surfus.Shell.Messages
{
    internal record Ignore : IClientMessage
    {
        public Ignore(SshPacket packet)
        {
            Data = packet.Reader.ReadString();
        }

        public Ignore(string data)
        {
            Data = data;
        }

        public string Data { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_IGNORE;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => Data.GetStringSize();

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteString(Data);
        }
    }
}
