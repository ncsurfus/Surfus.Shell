namespace Surfus.Shell.Messages.UserAuth
{
    internal record UaBanner : IMessage
    {
        public UaBanner(SshPacket packet)
        {
            Message = packet.Reader.ReadString();
            LanguageTag = packet.Reader.ReadString();
        }

        public string Message { get; }
        public string LanguageTag { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_BANNER;
        public byte MessageId => (byte)Type;
    }
}
