using System;
using System.IO;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.Channel.Requests;

namespace Surfus.Shell.Messages.Channel
{
    internal class ChannelRequest : IClientMessage, IChannelRecipient
    {
        protected ChannelRequest(SshPacket packet, string requestType, uint recipientChannel)
        {
            RecipientChannel = recipientChannel;
            RequestType = requestType;
            WantReply = packet.Reader.ReadBoolean();
        }

        public ChannelRequest(uint recipientChannel, string requestType, bool wantReply)
        {
            RecipientChannel = recipientChannel;
            RequestType = requestType;
            WantReply = wantReply;
        }

        public string RequestType { get; }
        public bool WantReply { get; }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_REQUEST;
        public byte MessageId => (byte)Type;

        public virtual ByteWriter GetByteWriter()
        {
            return GetByteWriter(0);
        }

        public static ChannelRequest FromBuffer(SshPacket packet)
        {
            var recipientChannel = packet.Reader.ReadUInt32();
            var requestType = packet.Reader.ReadAsciiString();

            switch (requestType)
            {
                case "exec":
                    return new ChannelRequestExec(packet, recipientChannel);
                case "shell":
                    return new ChannelRequestShell(packet, recipientChannel);
                case "subsystem":
                    return new ChannelRequestSubsystem(packet, recipientChannel);
                default:
                    return new ChannelRequest(packet, requestType, recipientChannel);
            }
        }

        protected ByteWriter GetByteWriter(int additionalSize)
        {
            var writer = new ByteWriter(Type, 4 + RequestType.GetAsciiStringSize() + 1 + additionalSize);
            writer.WriteUint(RecipientChannel);
            writer.WriteAsciiString(RequestType);
            writer.WriteByte(WantReply ? (byte)1 : (byte)0);
            return writer;
        }
    }
}
