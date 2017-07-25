namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    internal class DhgReply : IMessage
    {
        internal DhgReply(SshPacket packet)
        {
            ServerPublicHostKeyAndCertificates = packet.PayloadReader.ReadBinaryString();
            F = packet.PayloadReader.ReadBigInteger();
            HSignature = packet.PayloadReader.ReadBinaryString();
        }

        public BigInt F { get; }

        public byte[] HSignature { get; }

        public byte[] ServerPublicHostKeyAndCertificates { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_33;

        public byte MessageId => (byte)Type;
    }
}
