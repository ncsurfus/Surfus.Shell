using System.IO;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    public class DhgRequest : IMessage
    {
        public DhgRequest(uint min, uint n, uint max)
        {
            Min = min;
            N = n;
            Max = max;
        }

        internal DhgRequest(SshPacket packet)
        {
            Min = packet.Reader.ReadUInt32();
            N = packet.Reader.ReadUInt32();
            Max = packet.Reader.ReadUInt32();

        }

        public uint Min { get; }
        public uint Max { get; }
        public uint N { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_34;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(Min);
                memoryStream.WriteUInt(N);
                memoryStream.WriteUInt(Max);
                return memoryStream.ToArray();
            }
        }
    }
}
