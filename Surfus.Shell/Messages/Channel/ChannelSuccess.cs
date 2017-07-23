using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelSuccess : IMessage, IChannelRecipient
    {
        public ChannelSuccess(SshPacket packet)
        {
            RecipientChannel = packet.Reader.ReadUInt32();
        }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_SUCCESS;
        public byte MessageId => (byte)Type;
    }
}
