using System;
using System.IO;

namespace Surfus.Shell.Messages
{
    public class NewKeys : IMessage
    {
        public NewKeys(byte[] buffer)
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

        public NewKeys()
        {

        }

        public MessageType Type { get; } = MessageType.SSH_MSG_NEWKEYS;
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
