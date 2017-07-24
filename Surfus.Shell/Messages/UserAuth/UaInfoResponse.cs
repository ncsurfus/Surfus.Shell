namespace Surfus.Shell.Messages.UserAuth
{
    public class UaInfoResponse : IClientMessage
    {
        public UaInfoResponse(uint promptNumber, string[] responses)
        {
            PromptNumber = promptNumber;
            Responses = responses;
        }

        public uint PromptNumber { get; }
        public string[] Responses { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_INFO_RESPONSE;
        public byte MessageId => (byte)Type;

        public virtual ByteWriter GetByteWriter()
        {
            var size = 4;
            for (int i = 0; i != PromptNumber; i++)
            {
                size += Responses[i].GetStringSize();
            }

            var writer = new ByteWriter(Type, size);
            writer.WriteUint(PromptNumber);
            for (int i = 0; i != PromptNumber; i++)
            {
                writer.WriteString(Responses[i]);
            }
            return writer;
        }
    }
}
