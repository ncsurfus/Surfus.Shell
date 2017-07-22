namespace Surfus.Shell.Messages.KeyExchange.DiffieHellman
{
    internal class DhInit : IClientMessage
    {
        internal DhInit(BigInt e)
        {
            E = e;
        }

        internal BigInt E { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_30;
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
