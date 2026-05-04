using System;
using Surfus.Shell.Extensions;
using System.Security.Cryptography;

namespace Surfus.Shell.Messages.KeyExchange
{
    // Reference: https://tools.ietf.org/html/rfc4253#section-7.1
    internal record KexInit : IClientMessage
    {
        private static readonly RandomNumberGenerator RandomGenerator = RandomNumberGenerator.Create();

        public KexInit(SshAlgorithms algorithms)
        {
            RandomBytes = new byte[16];
            RandomGenerator.GetBytes(RandomBytes);

            KexAlgorithms = new NameList(algorithms.KeyExchangeNames);
            ServerHostKeyAlgorithms = new NameList(algorithms.HostKeyNames);
            EncryptionClientToServer = new NameList(algorithms.EncryptionNames);
            EncryptionServerToClient = new NameList(algorithms.EncryptionNames);
            MacClientToServer = new NameList(algorithms.MacNames);
            MacServerToClient = new NameList(algorithms.MacNames);
            CompressionClientToServer = new NameList(algorithms.CompressionNames);
            CompressionServerToClient = new NameList(algorithms.CompressionNames);
            LanguagesClientToServer = new NameList();
            LanguagesServerToClient = new NameList();

            Bytes = ComputeBytes();
        }

        internal KexInit(SshPacket packet)
        {
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
            Bytes = packet.Reader.Bytes.Slice(startPosition, packet.Reader.Position - startPosition + 4).ToArray();
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

        /// <summary>
        /// The raw bytes of this KexInit message (used for key exchange hash computation).
        /// </summary>
        public byte[] Bytes { get; }

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, GetSize() - 1);
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
            return ByteSizer.GetByteSize()
                + RandomBytes.AsMemory().GetByteBlobSize()
                + KexAlgorithms.GetNameListSize()
                + ServerHostKeyAlgorithms.GetNameListSize()
                + EncryptionClientToServer.GetNameListSize()
                + EncryptionServerToClient.GetNameListSize()
                + MacClientToServer.GetNameListSize()
                + MacServerToClient.GetNameListSize()
                + CompressionClientToServer.GetNameListSize()
                + CompressionServerToClient.GetNameListSize()
                + LanguagesClientToServer.GetNameListSize()
                + LanguagesServerToClient.GetNameListSize()
                + ByteSizer.GetByteSize()
                + ByteSizer.GetIntSize();
        }

        internal void WriteBytes(ByteWriter writer)
        {
            writer.WriteByteBlob(Bytes);
        }

        private byte[] ComputeBytes()
        {
            var writer = new ByteWriter(GetSize());
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
            return writer.Bytes;
        }
    }
}
