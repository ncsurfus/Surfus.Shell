using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelEof : IMessage, IChannelRecipient
    {
        public ChannelEof(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
        }

        public ChannelEof(uint recipientChannel)
        {
            RecipientChannel = recipientChannel;
        }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_EOF;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(RecipientChannel);
                return memoryStream.ToArray();
            }
        }
    }
}
