using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelOpenConfirmation : IMessage
    {
        public ChannelOpenConfirmation(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                RecipientChannel = stream.ReadUInt32();
                SenderChannel = stream.ReadUInt32();
                InitialWindowSize = stream.ReadUInt32();
                MaximumWindowSize = stream.ReadUInt32();
            }
        }

        public ChannelOpenConfirmation(uint senderChannel, uint recipentChannel)
        {
            RecipientChannel = recipentChannel;
            SenderChannel = senderChannel;
        }

        public uint RecipientChannel { get; }
        public uint SenderChannel { get; }
        public uint InitialWindowSize { get; } = 1024;
        public uint MaximumWindowSize { get; } = 32000;

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
        public byte MessageId => (byte)Type;

        public virtual byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(RecipientChannel);
                memoryStream.WriteUInt(SenderChannel);
                memoryStream.WriteUInt(InitialWindowSize);
                memoryStream.WriteUInt(MaximumWindowSize);
                return memoryStream.ToArray();
            }
        }
    }
}
