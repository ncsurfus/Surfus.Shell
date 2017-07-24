using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelClose : IClientMessage, IChannelRecipient
    {
        public ChannelClose(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
        }

        public ChannelClose(uint recipientChannel)
        {
            RecipientChannel = recipientChannel;
        }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_CLOSE;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            var writer = new ByteWriter(5);
            writer.WriteByte(MessageId);
            writer.WriteUint(RecipientChannel);
            return writer.Bytes;
        }
        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, 4);
            writer.WriteUint(RecipientChannel);
            return writer;
        }
    }
}
