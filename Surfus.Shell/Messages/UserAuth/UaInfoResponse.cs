using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaInfoResponse : IClientMessage
    {
        public UaInfoResponse(SshPacket packet)
        {
            PromptNumber = packet.Reader.ReadUInt32();
            for (var i = 0; i != PromptNumber; i++)
            {
                Responses[i] = packet.Reader.ReadString();
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
