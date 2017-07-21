using System;
using System.IO;
using System.Numerics;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    internal class DhgInit : IMessage
    {
        public DhgInit(BigInt e)
        {
            E = e;
        }

        internal DhgInit(SshPacket packet)
        {
            E = packet.Reader.ReadBigInteger();

        }

        public BigInt E { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_32;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteBigInteger(E);

                return memoryStream.ToArray();
            }
        }
    }
}
