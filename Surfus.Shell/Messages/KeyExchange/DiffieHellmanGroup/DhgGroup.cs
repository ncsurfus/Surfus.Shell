using System;
using System.IO;
using System.Numerics;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    internal class DhgGroup : IMessage
    {
        public DhgGroup(BigInt p, BigInt g)
        {
            P = p;
            G = g;
        }

        internal DhgGroup(SshPacket packet)
        {
            P = packet.Reader.ReadBigInteger();
            G = packet.Reader.ReadBigInteger();
        }

        public BigInt P { get; }
        public BigInt G { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_31;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteBigInteger(P);
                memoryStream.WriteBigInteger(G);
                return memoryStream.ToArray();
            }
        }
    }
}
