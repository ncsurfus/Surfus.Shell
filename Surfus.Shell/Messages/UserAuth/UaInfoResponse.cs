using System;

namespace Surfus.Shell.Messages.UserAuth
{
    internal record UaInfoResponse : IClientMessage
    {
        public UaInfoResponse(uint promptNumber, string[] responses)
        {
            if (responses.Length < promptNumber)
                throw new ArgumentException("Responses array is smaller than promptNumber.");
            PromptNumber = promptNumber;
            Responses = responses;
        }

        public uint PromptNumber { get; }
        public string[] Responses { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_INFO_RESPONSE;
        public byte MessageId => (byte)Type;

        public virtual int GetPayloadSize()
        {
            var size = 4;
            for (int i = 0; i != PromptNumber; i++)
            {
                size += Responses[i].GetStringSize();
            }
            return size;
        }

        public virtual void WritePayload(ref SpanWriter writer)
        {
            writer.WriteUInt32(PromptNumber);
            for (int i = 0; i != PromptNumber; i++)
            {
                writer.WriteString(Responses[i]);
            }
        }
    }
}
