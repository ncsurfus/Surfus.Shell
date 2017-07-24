using System;
using System.IO;

namespace Surfus.Shell.Messages
{
    public class NewKeys : IClientMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_NEWKEYS;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, 0);
            return writer;
        }
    }
}
