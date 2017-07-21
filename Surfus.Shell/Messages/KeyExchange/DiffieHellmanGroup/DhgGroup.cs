using System;
using System.IO;
using System.Numerics;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    public class DhgGroup : IMessage
    {
        public DhgGroup(BigInteger p, BigInteger g)
        {
            P = p;
            G = g;
        }

        internal DhgGroup(SshPacket packet)
        {
            P = packet.Reader.ReadBigInteger();
            G = packet.Reader.ReadBigInteger();
        }

        public BigInteger P { get; }
        public BigInteger G { get; }

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
