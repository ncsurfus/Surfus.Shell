namespace Surfus.Shell.Messages
{
    public class ServiceRequest : IClientMessage
    {
        public ServiceRequest(string serviceName)
        {
            ServiceName = serviceName;
        }

        public string ServiceName { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_SERVICE_REQUEST;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, ServiceName.GetStringSize());
            writer.WriteString(ServiceName);
            return writer;
        }
    }
}
