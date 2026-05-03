namespace Surfus.Shell.Messages.UserAuth
{
    internal class UaFailure : IMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_FAILURE;
        public byte MessageId => (byte)Type;
    }
}
