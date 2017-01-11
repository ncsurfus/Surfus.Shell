using System;
using System.IO;
using System.Numerics;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    public class DhgReply : IMessage
    {
        public DhgReply(byte[] serverPublicHostKeyAndCertificates, BigInteger f, byte[] hSignature)
        {
            ServerPublicHostKeyAndCertificates = serverPublicHostKeyAndCertificates;
            F = f;
            HSignature = hSignature;
        }

        internal DhgReply(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                ServerPublicHostKeyAndCertificates = stream.ReadBinaryString();
                F = stream.ReadBigInteger();
                HSignature = stream.ReadBinaryString();
            }
        }

        public BigInteger F { get; }

        public byte[] HSignature { get; }

        public byte[] ServerPublicHostKeyAndCertificates { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_33;

        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteBinaryString(ServerPublicHostKeyAndCertificates);
                memoryStream.WriteBigInteger(F);
                memoryStream.WriteBinaryString(HSignature);
                return memoryStream.ToArray();
            }
        }
    }
}
