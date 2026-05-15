namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    internal record DhgRequest : IClientMessage
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

        public int GetPayloadSize() => 12;

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteUInt32(Min);
            writer.WriteUInt32(N);
            writer.WriteUInt32(Max);
        }
    }
}
