using System;
using System.IO;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaFailure : IClientMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_FAILURE;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                return memoryStream.ToArray();
            }
        }
    }
}
