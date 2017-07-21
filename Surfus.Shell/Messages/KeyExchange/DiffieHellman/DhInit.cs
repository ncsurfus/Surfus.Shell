using System;
using System.IO;
using System.Numerics;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellman
{
    internal class DhInit : IMessage
    {
        internal DhInit(BigInt e)
        {
            E = e;
        }

        internal DhInit(SshPacket packet)
        {
            E = packet.Reader.ReadBigInteger();

        }

        internal BigInt E { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_30;
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
