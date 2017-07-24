namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    public class DhgRequest : IClientMessage
    {
        public DhgRequest(uint min, uint n, uint max)
        {
            Min = min;
            N = n;
            Max = max;
        }

        public uint Min { get; }
        public uint Max { get; }
        public uint N { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_34;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, 12);
            writer.WriteUint(Min);
            writer.WriteUint(N);
            writer.WriteUint(Max);
            return writer;
        }
    }
}
