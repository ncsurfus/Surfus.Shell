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

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, E.GetBigIntegerSize());
            writer.WriteBigInteger(E);
            return writer;
        }
    }
}
