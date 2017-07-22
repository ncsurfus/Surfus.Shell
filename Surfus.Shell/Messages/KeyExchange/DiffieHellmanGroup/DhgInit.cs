namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    internal class DhgInit : IClientMessage
    {
        public DhgInit(BigInt e)
        {
            E = e;
        }

        public BigInt E { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_32;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            var size = 1 + E.GetBigIntegerSize();
            var writer = new ByteWriter(size);
            writer.WriteByte(MessageId);
            writer.WriteBigInteger(E);
            return writer.Bytes;
        }
    }
}
