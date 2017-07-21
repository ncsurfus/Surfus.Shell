using System;
using System.IO;
using System.Numerics;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    public class DhgInit : IMessage
    {
        public DhgInit(BigInteger e)
        {
            E = e;
        }

        internal DhgInit(SshPacket packet)
        {
            E = packet.Reader.ReadBigInteger();

        }

        public BigInteger E { get; }

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
