using System;

namespace Surfus.Shell.Messages.KeyExchange.DiffieHellmanGroup
{
    internal record DhgInit : IClientMessage
    {
        public DhgInit(BigInt e)
        {
            E = e;
        }

        public BigInt E { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_32;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => 4 + E.Length;

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteUInt32((uint)E.Length);
            var dest = writer.Remaining.Slice(0, E.Length);
            if (!E.BigInteger.TryWriteBytes(dest, out _, isUnsigned: false, isBigEndian: true))
            {
                throw new Exceptions.SshException("Failed to write BigInteger.");
            }
            writer.WriteBytes(dest);
        }
    }
}
