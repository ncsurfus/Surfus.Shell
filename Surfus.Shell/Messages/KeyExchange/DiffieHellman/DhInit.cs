using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellman
{
    public class DhInit : IMessage
    {
        public DhInit(BigInteger e)
        {
            E = e;
        }

        internal DhInit(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                E = stream.ReadBigInteger();
            }
        }

        public BigInteger E { get; }

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
