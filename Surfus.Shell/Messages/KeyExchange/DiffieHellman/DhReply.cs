namespace Surfus.Shell.Messages.KeyExchange.DiffieHellman
{
    internal class DhReply : IMessage
    {
        internal DhReply(SshPacket packet)
        {
            ServerPublicHostKeyAndCertificates = packet.PayloadReader.ReadBinaryString();
            F = packet.PayloadReader.ReadBigInteger();
            HSignature = packet.PayloadReader.ReadBinaryString();
        }

        public BigInt F { get; }

        public byte[] HSignature { get; }

        public byte[] ServerPublicHostKeyAndCertificates { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_31;

        public byte MessageId => (byte)Type;
    }
}
