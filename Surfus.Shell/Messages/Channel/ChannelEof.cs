using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelEof : IClientMessage, IChannelRecipient
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
            var writer = new ByteWriter(5);
            writer.WriteByte(MessageId);
            writer.WriteUint(RecipientChannel);
            return writer.Bytes;
        }
    }
}
