namespace Surfus.Shell.Messages
{
    internal record ServiceRequest : IClientMessage
    {
        public ServiceRequest(string serviceName)
        {
            ServiceName = serviceName;
        }

        public string ServiceName { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_SERVICE_REQUEST;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => ServiceName.GetStringSize();

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteString(ServiceName);
        }
    }
}
