namespace Surfus.Shell.Messages
{
    public class ServiceAccept : IMessage
    {
        public ServiceAccept(SshPacket packet)
        {
            ServiceName = packet.Reader.ReadString();
        }
        public string ServiceName { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_SERVICE_ACCEPT;
        public byte MessageId => (byte)Type;
    }
}
