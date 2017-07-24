using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelData : IClientMessage, IChannelRecipient
    {
        private byte[] _data;

        public ChannelData(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            _data = packet.Reader.ReadBinaryString();
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

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, 4 + Data.GetBinaryStringSize());
            writer.WriteUint(RecipientChannel);
            writer.WriteBinaryString(Data);
            return writer;
        }
    }
}
