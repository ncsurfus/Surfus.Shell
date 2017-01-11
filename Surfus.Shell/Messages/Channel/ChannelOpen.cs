using System;
using System.IO;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.Channel.Open;

namespace Surfus.Shell.Messages.Channel
{
    public class ChannelOpen : IMessage
    {
        protected ChannelOpen(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                ChannelType = stream.ReadAsciiString();
                SenderChannel = stream.ReadUInt32();
                InitialWindowSize = stream.ReadUInt32();
                MaximumPacketSize = stream.ReadUInt32();
                BaseMemoryStreamPosition = stream.Position;
            }
        }

        public ChannelOpen(string channelType, uint senderChannel, uint initialWindowSize = 35000)
        {
            ChannelType = channelType;
            SenderChannel = senderChannel;
            InitialWindowSize = initialWindowSize;
        }

        protected long BaseMemoryStreamPosition { get; }

        public string ChannelType { get; }
        public uint SenderChannel { get; }
        public uint InitialWindowSize { get; }
        public uint MaximumPacketSize { get; } = 32000;

        public MessageType Type { get; } = MessageType.SSH_MSG_CHANNEL_OPEN;
        public byte MessageId => (byte)Type;

        public virtual byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteAsciiString(ChannelType);
                memoryStream.WriteUInt(SenderChannel);
                memoryStream.WriteUInt(InitialWindowSize);
                memoryStream.WriteUInt(MaximumPacketSize);
                return memoryStream.ToArray();
            }
        }

        public static ChannelOpen FromBuffer(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != (byte)MessageType.SSH_MSG_CHANNEL_OPEN)
                {
                    throw new Exception($"Expected Type: {MessageType.SSH_MSG_CHANNEL_OPEN}");
                }

                var channelType = stream.ReadAsciiString();

                switch (channelType)
                {
                    case "session":
                        return new ChannelOpenSession(buffer);
                    case "x11":
                        return new ChannelOpenX11(buffer);
                    case "forwarded-tcpip":
                        return new ChannelOpenForwardedTcpIp(buffer);
                    case "direct-tcpip":
                        return new ChannelOpenDirectTcpIp(buffer);
                    default:
                        return new ChannelOpen(buffer);
                }
            }
        }

        protected MemoryStream GetMemoryStream()
        {
            var memoryStream = new MemoryStream();

            memoryStream.WriteByte(MessageId);
            memoryStream.WriteAsciiString(ChannelType);
            memoryStream.WriteUInt(SenderChannel);
            memoryStream.WriteUInt(InitialWindowSize);
            memoryStream.WriteUInt(MaximumPacketSize);

            return memoryStream;
        }
    }
}
