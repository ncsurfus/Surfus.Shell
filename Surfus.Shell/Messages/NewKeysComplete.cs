using System;

namespace Surfus.Shell.Messages
{
    // Fake message that lets the writer to properly handle SSH Key Updates.
    internal record NewKeysComplete : IClientMessage
    {
        public MessageType Type { get; } = MessageType.SSH_MSG_NEWKEYS;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize()
        {
            throw new NotImplementedException();
        }

        public void WritePayload(ref SpanWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
