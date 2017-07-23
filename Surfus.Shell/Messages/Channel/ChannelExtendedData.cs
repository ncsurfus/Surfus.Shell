using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelExtendedData : IClientMessage, IChannelRecipient
    {
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        public enum DataType : uint
        {
            SSH_EXTENDED_DATA_STDERR = 1
        }

        public ChannelExtendedData(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            DataTypeCode = (DataType)packet.Reader.ReadUInt32();
            Data = packet.Reader.ReadBinaryString();
        }

        public ChannelExtendedData(uint recipientChannel, uint dataTypeCode, byte[] data)
        {
            RecipientChannel = recipientChannel;
            DataTypeCode = (DataType)dataTypeCode;
            Data = data;
        }

        public DataType DataTypeCode { get; }
        public byte[] Data { get; }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            var writer = new ByteWriter(9 + Data.GetBinaryStringSize());
            writer.WriteByte(MessageId);
            writer.WriteUint(RecipientChannel);
            writer.WriteUint((uint)DataTypeCode);
            writer.WriteBinaryString(Data);
            return writer.Bytes;
        }
    }
}
