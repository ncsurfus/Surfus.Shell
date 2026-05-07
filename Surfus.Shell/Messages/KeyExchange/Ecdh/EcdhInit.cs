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

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, ClientPublicKey.GetBinaryStringSize());
            writer.WriteBinaryString(ClientPublicKey);
            return writer;
        }
    }
}
