namespace Surfus.Shell.Messages
{
    internal class NewKeys : IClientMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_NEWKEYS;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, 0);
            return writer;
        }
    }
}
