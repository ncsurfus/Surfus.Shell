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
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(RecipientChannel);
                memoryStream.WriteUInt((uint)DataTypeCode);
                memoryStream.WriteBinaryString(Data);
                return memoryStream.ToArray();
            }
        }
    }
}
