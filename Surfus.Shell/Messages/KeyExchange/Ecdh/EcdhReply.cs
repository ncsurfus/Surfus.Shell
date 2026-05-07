using System;

namespace Surfus.Shell.Messages.KeyExchange.Ecdh
{
    internal record EcdhReply : IMessage
    {
        internal EcdhReply(SshPacket packet)
        {
            ServerPublicHostKeyAndCertificates = packet.Reader.ReadBinaryString();
            ServerPublicKey = packet.Reader.ReadBinaryString();
            HSignature = packet.Reader.ReadBinaryString();
        }

        public ReadOnlyMemory<byte> ServerPublicHostKeyAndCertificates { get; }
        public ReadOnlyMemory<byte> ServerPublicKey { get; }
        public ReadOnlyMemory<byte> HSignature { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_31;
        public byte MessageId => (byte)Type;
    }
}
