using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelData : IMessage, IChannelRecipient
    {
        private byte[] _data;

        public ChannelData(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                RecipientChannel = stream.ReadUInt32();
                _data = stream.ReadBinaryString();
            }
        }

        public ChannelData(uint recipientChannel, byte[] data)
        {
            RecipientChannel = recipientChannel;
            _data = data;
        }

        public byte[] Data => _data;

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_DATA;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(RecipientChannel);
                memoryStream.WriteBinaryString(Data);
                return memoryStream.ToArray();
            }
        }

        public void ResizeData(int length)
        {
            Array.Resize(ref _data, length);
        }
    }
}
