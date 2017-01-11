using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.EcDiffieHellman
{
    internal class EcDhInit : IMessage
   {
        internal EcDhInit(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                Key = stream.ReadBinaryString();
            }
        }

        public byte[] Key { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_32;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteBinaryString(Key);

                return memoryStream.ToArray();
            }
        }
    }
}
