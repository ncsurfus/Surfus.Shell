using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages
{
    public class Unimplemented : IMessage
    {
        public Unimplemented(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                PacketSequenceNumber = stream.ReadUInt32();
            }
        }

        public Unimplemented(uint packetSequenceNumber)
        {
            PacketSequenceNumber = packetSequenceNumber;
        }

        public uint PacketSequenceNumber { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_UNIMPLEMENTED;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(PacketSequenceNumber);
                return memoryStream.ToArray();
            }
        }
    }
}
