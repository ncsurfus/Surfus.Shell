using System;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.Extensions;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.MessageAuthentication;
using Surfus.Shell.Signing;
using System.Security.Cryptography;
using System.Linq;

namespace Surfus.Shell.Messages.KeyExchange
{
    // Reference: https://tools.ietf.org/html/rfc4253#section-7.1
    public class KexInit : IClientMessage
    {
        private static readonly RandomNumberGenerator RandomGenerator = RandomNumberGenerator.Create();

        public KexInit()
        {
            RandomBytes = new byte[16];
            RandomGenerator.GetBytes(RandomBytes);

            KexAlgorithms = new NameList(KeyExchangeAlgorithm.Supported);
            ServerHostKeyAlgorithms = new NameList(Signer.Supported);
            EncryptionClientToServer = new NameList(CryptoAlgorithm.Supported);
            EncryptionServerToClient = new NameList(CryptoAlgorithm.Supported);
            MacClientToServer = new NameList(MacAlgorithm.Supported);
            MacServerToClient = new NameList(MacAlgorithm.Supported);
            CompressionClientToServer = new NameList(CompressionAlgorithm.Supported);
            CompressionServerToClient = new NameList(CompressionAlgorithm.Supported);
            LanguagesClientToServer = new NameList();
            LanguagesServerToClient = new NameList();
        }

        internal KexInit(SshPacket packet)
        {
            // Backup the start position we can also grab the message id in the segement.
            var startPosition = packet.PayloadReader.Position - 1;
            RandomBytes = packet.PayloadReader.Read(16);
            KexAlgorithms = packet.PayloadReader.ReadNameList();
            ServerHostKeyAlgorithms = packet.PayloadReader.ReadNameList();
            EncryptionClientToServer = packet.PayloadReader.ReadNameList();
            EncryptionServerToClient = packet.PayloadReader.ReadNameList();
            MacClientToServer = packet.PayloadReader.ReadNameList();
            MacServerToClient = packet.PayloadReader.ReadNameList();
            CompressionClientToServer = packet.PayloadReader.ReadNameList();
            CompressionServerToClient = packet.PayloadReader.ReadNameList();
            LanguagesClientToServer = packet.PayloadReader.ReadNameList();
            LanguagesServerToClient = packet.PayloadReader.ReadNameList();
            FirstKexPacketFollows = packet.PayloadReader.ReadBoolean();
            // Add 4 to end position to grab the last uint32 that is to be ignored.
            _bytes = new ArraySegment<byte>(packet.PayloadReader.Bytes, startPosition, packet.PayloadReader.Position - startPosition + 4);
        }

        public NameList CompressionClientToServer { get; }

        public NameList CompressionServerToClient { get; }

        public NameList EncryptionClientToServer { get; }

        public NameList EncryptionServerToClient { get; }

        public bool FirstKexPacketFollows { get; }

        public NameList KexAlgorithms { get; }

        public NameList LanguagesClientToServer { get; }

        public NameList LanguagesServerToClient { get; }

        public NameList MacClientToServer { get; }

        public NameList MacServerToClient { get; }

        public byte[] RandomBytes { get; }

        public NameList ServerHostKeyAlgorithms { get; }

        public MessageType Type => MessageType.SSH_MSG_KEXINIT;

        public byte MessageId => (byte)Type;

        private ArraySegment<byte> _bytes { get; set; }

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, GetSize() - 1); // Take off the initial message size.
            writer.WriteByteBlob(RandomBytes);
            writer.WriteNameList(KexAlgorithms);
            writer.WriteNameList(ServerHostKeyAlgorithms);
            writer.WriteNameList(EncryptionClientToServer);
            writer.WriteNameList(EncryptionServerToClient);
            writer.WriteNameList(MacClientToServer);
            writer.WriteNameList(MacServerToClient);
            writer.WriteNameList(CompressionClientToServer);
            writer.WriteNameList(CompressionServerToClient);
            writer.WriteNameList(LanguagesClientToServer);
            writer.WriteNameList(LanguagesServerToClient);
            writer.WriteByte(FirstKexPacketFollows ? (byte)1 : (byte)0);
            writer.WriteUint(0);
            return writer;
        }

        public int GetSize()
        {
            //if(_bytes.Array != null)
           // {
            //    return _bytes.Count;
           // }
            return ByteSizer.GetByteSize() +
                   RandomBytes.GetByteBlobSize() +
                   KexAlgorithms.GetNameListSize() +
                   ServerHostKeyAlgorithms.GetNameListSize() +
                   EncryptionClientToServer.GetNameListSize() +
                   EncryptionServerToClient.GetNameListSize() +
                   MacClientToServer.GetNameListSize() +
                   MacServerToClient.GetNameListSize() +
                   CompressionClientToServer.GetNameListSize() +
                   CompressionServerToClient.GetNameListSize() +
                   LanguagesClientToServer.GetNameListSize() +
                   LanguagesServerToClient.GetNameListSize() +
                   ByteSizer.GetByteSize() + 
                   ByteSizer.GetIntSize();
        }

        internal void WriteBytes(ByteWriter writer)
        {
            if(_bytes.Array != null)
            {
                writer.WriteByteBlob(_bytes);
                return;
            }
            var start = writer.Position;
            writer.WriteByte(MessageId);
            writer.WriteByteBlob(RandomBytes);
            writer.WriteNameList(KexAlgorithms);
            writer.WriteNameList(ServerHostKeyAlgorithms);
            writer.WriteNameList(EncryptionClientToServer);
            writer.WriteNameList(EncryptionServerToClient);
            writer.WriteNameList(MacClientToServer);
            writer.WriteNameList(MacServerToClient);
            writer.WriteNameList(CompressionClientToServer);
            writer.WriteNameList(CompressionServerToClient);
            writer.WriteNameList(LanguagesClientToServer);
            writer.WriteNameList(LanguagesServerToClient);
            writer.WriteByte(FirstKexPacketFollows ? (byte)1 : (byte)0);
            writer.WriteUint(0);
            _bytes = new ArraySegment<byte>(writer.Bytes, start, writer.Position - start);
        }
    }
}
