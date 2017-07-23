using System;
using System.IO;

namespace Surfus.Shell.Messages
{
    public class NewKeys : IClientMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_NEWKEYS;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            var writer = new ByteWriter(1);
            writer.WriteByte(MessageId);
            return writer.Bytes;
        }
    }
}
