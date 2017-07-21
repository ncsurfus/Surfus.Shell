using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelOpenFailure : IMessage, IChannelRecipient
    {
        public ChannelOpenFailure(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
            ReasonCode = packet.Reader.ReadUInt32();
            Description = packet.Reader.ReadString();
            Language = packet.Reader.ReadString();
        }

        public ChannelOpenFailure(uint recipentChannel, uint reasonCode, string description, string language = null)
        {
            RecipientChannel = recipentChannel;
            ReasonCode = reasonCode;
            Description = description;
            Language = language;
        }

        public uint RecipientChannel { get; }
        public uint ReasonCode { get; }
        public string Description { get; }
        public string Language { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(RecipientChannel);
                memoryStream.WriteUInt(ReasonCode);
                memoryStream.WriteString(Description);
                memoryStream.WriteString(Language);
                return memoryStream.ToArray();
            }
        }
    }
}
