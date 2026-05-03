namespace Surfus.Shell.Messages.UserAuth
{
    internal record UaFailure : IMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_FAILURE;
        public byte MessageId => (byte)Type;
    }
}
