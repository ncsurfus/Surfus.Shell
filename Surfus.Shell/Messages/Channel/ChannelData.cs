using System;

namespace Surfus.Shell.Messages.Channel
{
    internal record ChannelData : IClientMessage
    {
        public ChannelData(uint recipientChannel, ReadOnlyMemory<byte> data)
        {
            RecipientChannel = recipientChannel;
            Data = data;
        }

        public ReadOnlyMemory<byte> Data { get; }
        public uint RecipientChannel { get; }
        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_DATA;

        public int GetPayloadSize() => 4 + 4 + Data.Length; // recipient + length prefix + data

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteUInt32(RecipientChannel);
            writer.WriteBinaryString(Data.Span);
        }
    }
}
