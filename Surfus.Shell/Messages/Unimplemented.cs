using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages
{
    public class Unimplemented : IClientMessage
    {
        public Unimplemented(SshPacket packet)
        {
            PacketSequenceNumber = packet.Reader.ReadUInt32();
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
