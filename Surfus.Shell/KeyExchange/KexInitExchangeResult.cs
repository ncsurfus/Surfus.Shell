using System;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell.KeyExchange
{
    /// <summary>
    /// Holds the negotiated algorithms and raw KexInit bytes for exchange hash computation.
    /// </summary>
    public record KexInitExchangeResult
    {
        internal KexInitExchangeResult(
            KexInit client,
            ReadOnlyMemory<byte> serverBytes,
            string keyExchangeAlgorithm,
            string serverHostKeyAlgorithm,
            string encryptionClientToServer,
            string encryptionServerToClient,
            string messageAuthenticationClientToServer,
            string messageAuthenticationServerToClient,
            string compressionClientToServer,
            string compressionServerToClient)
        {
            ClientBytes = client.Bytes;
            ServerBytes = serverBytes;
            KeyExchangeAlgorithm = keyExchangeAlgorithm;
            ServerHostKeyAlgorithm = serverHostKeyAlgorithm;
            EncryptionClientToServer = encryptionClientToServer;
            EncryptionServerToClient = encryptionServerToClient;
            MessageAuthenticationClientToServer = messageAuthenticationClientToServer;
            MessageAuthenticationServerToClient = messageAuthenticationServerToClient;
            CompressionClientToServer = compressionClientToServer;
            CompressionServerToClient = compressionServerToClient;
        }

        internal ReadOnlyMemory<byte> ClientBytes { get; }
        internal ReadOnlyMemory<byte> ServerBytes { get; }
        internal int ClientBinaryStringSize => 4 + ClientBytes.Length;
        internal int ServerBinaryStringSize => 4 + ServerBytes.Length;

        internal string KeyExchangeAlgorithm { get; }
        internal string ServerHostKeyAlgorithm { get; }
        internal string EncryptionClientToServer { get; }
        internal string EncryptionServerToClient { get; }
        internal string CompressionClientToServer { get; }
        internal string CompressionServerToClient { get; }
        internal string MessageAuthenticationClientToServer { get; }
        internal string MessageAuthenticationServerToClient { get; }
    }
}
