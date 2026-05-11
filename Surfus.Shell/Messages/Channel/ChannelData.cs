using System;

namespace Surfus.Shell.Messages.Channel
{
    internal record ChannelData : IClientMessage, IChannelRecipient
    {
        public ChannelData(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            DataArray = packet.Reader.ReadBinaryString();
        }

        public ChannelData(uint recipientChannel, ReadOnlyMemory<byte> data)
        {
            RecipientChannel = recipientChannel;
            DataArray = data.ToArray();
        }

        /// <summary>
        /// The raw data array. Use this to avoid an extra copy when pushing to ChannelStream.
        /// </summary>
        internal byte[] DataArray { get; }

        public ReadOnlyMemory<byte> Data => DataArray;

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
