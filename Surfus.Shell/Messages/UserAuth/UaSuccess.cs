namespace Surfus.Shell.Messages.UserAuth
{
    internal record UaSuccess : IMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_SUCCESS;
        public byte MessageId => (byte)Type;
    }
}
