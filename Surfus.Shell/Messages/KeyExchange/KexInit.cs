using System;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.Extensions;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.MessageAuthentication;
using Surfus.Shell.Signing;
using System.Security.Cryptography;

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
            var startPosition = packet.Reader.Position - 1;
            RandomBytes = packet.Reader.Read(16);
            KexAlgorithms = packet.Reader.ReadNameList();
            ServerHostKeyAlgorithms = packet.Reader.ReadNameList();
            EncryptionClientToServer = packet.Reader.ReadNameList();
            EncryptionServerToClient = packet.Reader.ReadNameList();
            MacClientToServer = packet.Reader.ReadNameList();
            MacServerToClient = packet.Reader.ReadNameList();
            CompressionClientToServer = packet.Reader.ReadNameList();
            CompressionServerToClient = packet.Reader.ReadNameList();
            LanguagesClientToServer = packet.Reader.ReadNameList();
            LanguagesServerToClient = packet.Reader.ReadNameList();
            FirstKexPacketFollows = packet.Reader.ReadBoolean();
            // Add 4 to end position to grab the last uint32 that is to be ignored.
            _bytes = packet.Reader.Bytes.Slice(startPosition, packet.Reader.Position - startPosition + 4);
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

        private ReadOnlyMemory<byte> _bytes { get; set; }

        public ReadOnlyMemory<byte> GetBytes()
        {
            if(!_bytes.IsEmpty)
            {
                return _bytes;
            }
            var byteWriter = new ByteWriter(GetSize());
            WriteBytes(byteWriter);
            _bytes = byteWriter.Bytes.AsMemory();
            return byteWriter.Bytes.AsMemory();
        }

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
            if(!_bytes.IsEmpty)
            {
                writer.WriteByteBlob(_bytes.Span);
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
            _bytes = writer.Bytes.AsMemory(start, writer.Position - start);
        }
    }
}
