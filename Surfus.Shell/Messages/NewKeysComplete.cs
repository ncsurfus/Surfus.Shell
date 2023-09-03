using System;

namespace Surfus.Shell.Messages
{
    // Fake message that lets the writer to properly handle SSH Key Updates.
    public class NewKeysComplete : IClientMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_NEWKEYS;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            throw new NotImplementedException();
        }
    }
}
