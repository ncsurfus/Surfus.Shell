﻿using System;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    internal class DhgReply : IMessage
    {
        internal DhgReply(SshPacket packet)
        {
            ServerPublicHostKeyAndCertificates = packet.Reader.ReadBinaryString();
            F = packet.Reader.ReadBigInteger();
            HSignature = packet.Reader.ReadBinaryString();
        }

        public BigInt F { get; }

        public ReadOnlyMemory<byte> HSignature { get; }

        public ReadOnlyMemory<byte> ServerPublicHostKeyAndCertificates { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_33;

        public byte MessageId => (byte)Type;
    }
}
