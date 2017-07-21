using System;
using System.IO;
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
    public class KexInit : IMessage
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

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.Write(RandomBytes);
                memoryStream.WriteNameList(KexAlgorithms);
                memoryStream.WriteNameList(ServerHostKeyAlgorithms);
                memoryStream.WriteNameList(EncryptionClientToServer);
                memoryStream.WriteNameList(EncryptionServerToClient);
                memoryStream.WriteNameList(MacClientToServer);
                memoryStream.WriteNameList(MacServerToClient);
                memoryStream.WriteNameList(CompressionClientToServer);
                memoryStream.WriteNameList(CompressionServerToClient);
                memoryStream.WriteNameList(LanguagesClientToServer);
                memoryStream.WriteNameList(LanguagesServerToClient);
                memoryStream.WriteByte(FirstKexPacketFollows ? (byte)1 : (byte)0);
                memoryStream.WriteUInt(0);

                return memoryStream.ToArray();
            }
        }
    }
}
