using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelWindowAdjust : IMessage, IChannelRecipient
    {
        public ChannelWindowAdjust(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                RecipientChannel = stream.ReadUInt32();
                BytesToAdd = stream.ReadUInt32();
            }
        }

        public ChannelWindowAdjust(uint recipientChannel, uint bytesToAdd)
        {
            RecipientChannel = recipientChannel;
            BytesToAdd = bytesToAdd;
        }

        public uint BytesToAdd { get; }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(RecipientChannel);
                memoryStream.WriteUInt(BytesToAdd);
                return memoryStream.ToArray();
            }
        }
    }
}
