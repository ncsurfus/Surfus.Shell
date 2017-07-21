﻿using System;
using System.IO;
using System.Numerics;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellman
{
    public class DhReply : IMessage
    {
        public DhReply(byte[] serverPublicHostKeyAndCertificates, BigInteger f, byte[] hSignature)
        {
            ServerPublicHostKeyAndCertificates = serverPublicHostKeyAndCertificates;
            F = f;
            HSignature = hSignature;
        }

        internal DhReply(SshPacket packet)
        {
            ServerPublicHostKeyAndCertificates = packet.Reader.ReadBinaryString();
            F = packet.Reader.ReadBigInteger();
            HSignature = packet.Reader.ReadBinaryString();
        }

        public BigInteger F { get; }

        public byte[] HSignature { get; }

        public byte[] ServerPublicHostKeyAndCertificates { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_31;

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
