using System;
using System.IO;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.Channel.Requests;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelRequest : IMessage, IChannelRecipient
    {
        protected ChannelRequest(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                RecipientChannel = stream.ReadUInt32();
                RequestType = stream.ReadAsciiString();
                WantReply = stream.ReadBoolean();
                BaseMemoryStreamPosition = stream.Position;
            }
        }

        public ChannelRequest(uint recipientChannel, string requestType, bool wantReply)
        {
            RecipientChannel = recipientChannel;
            RequestType = requestType;
            WantReply = wantReply;
        }

        protected long BaseMemoryStreamPosition { get; }
        public string RequestType { get; }
        public bool WantReply { get; }

        public uint RecipientChannel { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_REQUEST;
        public byte MessageId => (byte)Type;

        public virtual byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(RecipientChannel);
                memoryStream.WriteAsciiString(RequestType);
                memoryStream.WriteByte(WantReply ? (byte) 1 : (byte)0);
                return memoryStream.ToArray();
            }
        }

        public static ChannelRequest FromBuffer(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != (byte)MessageType.SSH_MSG_CHANNEL_REQUEST)
                {
                    throw new Exception($"Expected Type: {MessageType.SSH_MSG_CHANNEL_REQUEST}");
                }

                stream.ReadUInt32();
                var requestType = stream.ReadAsciiString();

                switch (requestType)
                {
                    case "exec":
                        return new ChannelRequestExec(buffer);
                    case "shell":
                        return new ChannelRequestShell(buffer);
                    case "subsystem":
                        return new ChannelRequestSubsystem(buffer);
                    default:
                        return new ChannelRequest(buffer);
                }
            }
        }

        protected MemoryStream GetMemoryStream()
        {
            var memoryStream = new MemoryStream();

            memoryStream.WriteByte(MessageId);
            memoryStream.WriteUInt(RecipientChannel);
            memoryStream.WriteAsciiString(RequestType);
            memoryStream.WriteByte(WantReply ? (byte) 1 : (byte) 0);

            return memoryStream;
        }
    }
}
