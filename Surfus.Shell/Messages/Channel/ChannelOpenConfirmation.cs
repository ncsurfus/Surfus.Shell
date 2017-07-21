using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelOpenConfirmation : IMessage, IChannelRecipient
    {
        public ChannelOpenConfirmation(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            SenderChannel = packet.Reader.ReadUInt32();
            InitialWindowSize = packet.Reader.ReadUInt32();
            MaximumWindowSize = packet.Reader.ReadUInt32();
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
