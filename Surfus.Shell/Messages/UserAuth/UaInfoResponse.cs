using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaInfoResponse : IMessage
    {
        public UaInfoResponse(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                PromptNumber = stream.ReadUInt32();

                for (int i = 0; i != PromptNumber; i++)
                {
                    Responses[i] = stream.ReadString();
                }
            }
        }

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
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);

                memoryStream.WriteUInt(PromptNumber);

                for (int i = 0; i != PromptNumber; i++)
                {
                     memoryStream.WriteString(Responses[i]);
                }

                return memoryStream.ToArray();
            }
        }
    }
}
