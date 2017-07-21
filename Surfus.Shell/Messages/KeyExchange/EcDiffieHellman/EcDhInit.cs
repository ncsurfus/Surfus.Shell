using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.EcDiffieHellman
{
    internal class EcDhInit : IMessage
   {
       internal EcDhInit(SshPacket packet)
       {
           Key = packet.Reader.ReadBinaryString();
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
