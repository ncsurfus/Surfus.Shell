namespace Surfus.Shell.Messages
{
    internal record ServiceAccept : IMessage
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
