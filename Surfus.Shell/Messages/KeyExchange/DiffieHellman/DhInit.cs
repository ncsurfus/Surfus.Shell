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

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, E.GetBigIntegerSize());
            writer.WriteBigInteger(E);
            return writer;
        }
    }
}
