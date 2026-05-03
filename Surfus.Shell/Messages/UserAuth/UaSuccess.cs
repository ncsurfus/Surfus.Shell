namespace Surfus.Shell.Messages.UserAuth
{
    internal class UaSuccess : IMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_SUCCESS;
        public byte MessageId => (byte)Type;
    }
}
