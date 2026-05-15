namespace Surfus.Shell.Messages
{
    internal record NewKeys : IClientMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_NEWKEYS;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => 0;

        public void WritePayload(ref SpanWriter writer) { }
    }
}
