using System;

namespace Surfus.Shell.Messages.KeyExchange.Ecdh
{
    internal record EcdhInit : IClientMessage
    {
        internal EcdhInit(ReadOnlyMemory<byte> clientPublicKey)
        {
            ClientPublicKey = clientPublicKey;
        }

        internal ReadOnlyMemory<byte> ClientPublicKey { get; }

        public MessageType Type => MessageType.SSH_MSG_KEX_Exchange_30;
        public byte MessageId => (byte)Type;

        public int GetPayloadSize() => 4 + ClientPublicKey.Length;

        public void WritePayload(ref SpanWriter writer)
        {
            writer.WriteBinaryString(ClientPublicKey);
        }
    }
}
