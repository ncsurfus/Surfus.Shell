using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.MessageAuthentication;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell
{
    /// <summary>
    /// Negotiates ciphers and crypo settings with an Ssh server.
    /// </summary>
    public class SshKeyExchanger
    {
        private record CryptoConfig(
            Memory<byte> SessionIdentifier,
            Memory<byte> H,
            BigInt K,
            KeyExchangeAlgorithm KexAlgorithm,
            KexInitExchangeResult KexResult
        );

        private readonly SshClient _client;
        private readonly ChannelReader<MessageEvent> _channelReader;

        private static bool FilterMessage(MessageEvent message)
        {
            return message.Type switch
            {
                MessageType.SSH_MSG_KEX_Exchange_30
                or MessageType.SSH_MSG_KEX_Exchange_31
                or MessageType.SSH_MSG_KEX_Exchange_32
                or MessageType.SSH_MSG_KEX_Exchange_33
                or MessageType.SSH_MSG_KEX_Exchange_34
                or MessageType.SSH_MSG_KEXINIT
                or MessageType.SSH_MSG_NEWKEYS
                    => true,
                _ => false,
            };
        }

        /// <summary>
        /// Create the SshKeyExchanger.
        /// </summary>
        /// <param name="client">The SshClient used to receive and send messages.</param>
        public SshKeyExchanger(SshClient client)
        {
            _client = client;
            _channelReader = _client.RegisterMessageHandler(FilterMessage);
        }

        /// <summary>
        /// Returns true if the message starts a key exchange.
        /// </summary>
        public bool IsKeyExchangeStart(MessageEvent message)
        {
            return message.Type is MessageType.SSH_MSG_KEXINIT;
        }

        /// <summary>
        /// Returns true if the message starts a key exchange.
        /// </summary>
        public bool IsKeyExchangeEnd(MessageEvent message)
        {
            return message.Type is MessageType.SSH_MSG_NEWKEYS;
        }

        /// <summary>
        /// Starts the Key Exchange process.
        /// </summary>
        /// <param name="cancellationToken">Stops the key exchange.</param>
        public async Task StartKeyExchangeAsync(CancellationToken cancellationToken)
        {
            Memory<byte> sessionIdentifier = Memory<byte>.Empty;
            // Start waiting for the server's KexInit.
            // If this isn't the first exchange, then just await until the server wants to start the exchange.
            var serverKexInitTask = _channelReader.ReadAsync<KexInit>(cancellationToken).AsTask();
            if (!sessionIdentifier.IsEmpty)
            {
                await serverKexInitTask.ConfigureAwait(false);
            }

            // If this is the first exchange or we've received the server's KeyExchange then send KexInit.
            var clientKexInit = new KexInit();
            await _client.WriteMessageAsync(clientKexInit, cancellationToken).ConfigureAwait(false);
            var serverKexInit = await serverKexInitTask.ConfigureAwait(false);

            // Determine what the negotiated algorithms are.
            var kexInitResult = new KexInitExchangeResult(clientKexInit, serverKexInit);
            var kexAlgorithm = KeyExchangeAlgorithm.Create(_client, kexInitResult);
            var (h, k) = await kexAlgorithm.ExchangeAsync(_channelReader, cancellationToken).ConfigureAwait(false);

            // Wait for SSH_MSG_NEWKEYS and prevent any new mes
            await _channelReader.ReadAsync(MessageType.SSH_MSG_NEWKEYS, cancellationToken).ConfigureAwait(false);

            // Send our own SSH_MSG_NEWKEYS message.
            await _client.WriteMessageAsync(new NewKeys(), cancellationToken).ConfigureAwait(false);

            // Begin crypto rotation.
            sessionIdentifier = sessionIdentifier.IsEmpty ? h : sessionIdentifier;
            var cryptoConfig = new CryptoConfig(sessionIdentifier, h, k, kexAlgorithm, kexInitResult);
            ApplyKeyExchange(cryptoConfig);

            await _client.WriteMessageAsync(new NewKeysComplete(), cancellationToken).ConfigureAwait(false);
        }

        private void ApplyKeyExchange(CryptoConfig cryptoConfig)
        {
            var (sessionIdentifier, h, k, kexAlgorithm, kexResult) = cryptoConfig;
            var connectionInfo = _client.ConnectionInfo;

            // Assign new Algorithms
            connectionInfo.ReadCompressionAlgorithm = CompressionAlgorithm.Create(kexResult.CompressionServerToClient);
            connectionInfo.WriteCompressionAlgorithm = CompressionAlgorithm.Create(kexResult.CompressionClientToServer);
            connectionInfo.ReadCryptoAlgorithm = CryptoAlgorithm.Create(kexResult.EncryptionServerToClient);
            connectionInfo.WriteCryptoAlgorithm = CryptoAlgorithm.Create(kexResult.EncryptionClientToServer);
            connectionInfo.ReadMacAlgorithm = MacAlgorithm.Create(kexResult.MessageAuthenticationServerToClient);
            connectionInfo.WriteMacAlgorithm = MacAlgorithm.Create(kexResult.MessageAuthenticationClientToServer);

            // Get Keys
            var writeIv = kexAlgorithm.GenerateKey(
                h,
                k,
                'A',
                sessionIdentifier,
                connectionInfo.WriteCryptoAlgorithm.InitializationVectorSize
            );
            var readIv = kexAlgorithm.GenerateKey(
                h,
                k,
                'B',
                sessionIdentifier,
                connectionInfo.ReadCryptoAlgorithm.InitializationVectorSize
            );
            var writeEncryptionKey = kexAlgorithm.GenerateKey(h, k, 'C', sessionIdentifier, connectionInfo.WriteCryptoAlgorithm.KeySize);
            var readEncryptionKey = kexAlgorithm.GenerateKey(h, k, 'D', sessionIdentifier, connectionInfo.ReadCryptoAlgorithm.KeySize);
            var writeIntegrityKey = kexAlgorithm.GenerateKey(h, k, 'E', sessionIdentifier, connectionInfo.WriteMacAlgorithm.KeySize);
            var readIntegrityKey = kexAlgorithm.GenerateKey(h, k, 'F', sessionIdentifier, connectionInfo.ReadMacAlgorithm.KeySize);

            // Initialize Keys
            connectionInfo.ReadCryptoAlgorithm.Initialize(readIv, readEncryptionKey);
            connectionInfo.WriteCryptoAlgorithm.Initialize(writeIv, writeEncryptionKey);
            connectionInfo.ReadMacAlgorithm.Initialize(readIntegrityKey);
            connectionInfo.WriteMacAlgorithm.Initialize(writeIntegrityKey);
        }
    }
}
