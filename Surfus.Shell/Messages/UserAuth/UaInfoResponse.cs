using System;
using System.IO;
using Surfus.Shell.Extensions;

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

        public virtual byte[] GetBytes()
        {
            var size = 1 + 4;
            for (int i = 0; i != PromptNumber; i++)
            {
                size += Responses[i].GetStringSize();
            }

            var writer = new ByteWriter(size);
            writer.WriteByte(MessageId);
            writer.WriteUint(PromptNumber);
            for (int i = 0; i != PromptNumber; i++)
            {
                writer.WriteString(Responses[i]);
            }
            return writer.Bytes;
        }
    }
}
