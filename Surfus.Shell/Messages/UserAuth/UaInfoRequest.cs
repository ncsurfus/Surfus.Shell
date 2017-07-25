namespace Surfus.Shell.Messages.UserAuth
{
    public class UaInfoRequest : IMessage
    {
        public UaInfoRequest(SshPacket packet)
        {
            Name = packet.PayloadReader.ReadString();
            Instruction = packet.PayloadReader.ReadString();
            Language = packet.PayloadReader.ReadString();
            PromptNumber = packet.PayloadReader.ReadUInt32();
            Prompt = new string[PromptNumber];
            Echo = new bool[PromptNumber];
            for (var i = 0; i != PromptNumber; i++)
            {
                Prompt[i] = packet.PayloadReader.ReadString();
                Echo[i] = packet.PayloadReader.ReadBoolean();
            }
        }
        public string Name { get; }
        public string Instruction { get; }
        public string Language { get; }
        public uint PromptNumber { get; }
        public string[] Prompt { get; }
        public bool[] Echo { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_INFO_REQUEST;
        public byte MessageId => (byte)Type;
    }
}
