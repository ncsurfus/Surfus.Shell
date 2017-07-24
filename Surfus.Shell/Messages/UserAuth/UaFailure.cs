namespace Surfus.Shell.Messages.UserAuth
{
    public class UaFailure : IMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_FAILURE;
        public byte MessageId => (byte)Type;
    }
}
