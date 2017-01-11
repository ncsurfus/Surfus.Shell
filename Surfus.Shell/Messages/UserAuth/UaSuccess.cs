using System;
using System.IO;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaSuccess : IMessage
    {
        public UaSuccess(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }
            }
        }

        public UaSuccess()
        {

        }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_SUCCESS;
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
