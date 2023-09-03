using System;
using System.Threading;
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
        private readonly TaskCompletionSource _ready = new();
        private readonly TaskCompletionSource _initialKexComplete = new();

        /// <summary>
        /// Create the SshKeyExchanger.
        /// </summary>
        /// <param name="client">The SshClient used to receive and send messages.</param>
        public SshKeyExchanger(SshClient client)
        {
            _client = client;
        }

        /// <summary>
        /// This task completes once the SshKeyExchanger is listening for incoming messages.
        /// </summary>
        public Task Ready => _ready.Task;

        /// <summary>
        /// This task completes once the first key exchange completes..
        /// </summary>
        public Task InitialKeyExchangeComplete => _initialKexComplete.Task;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cancellationToken">Stops the key exchange.</param>
        public async Task HandleKeyExchangeAsync(CancellationToken cancellationToken)
        {
            using (cancellationToken.Register(() => _ready.TrySetCanceled()))
            using (cancellationToken.Register(() => _ready.TrySetCanceled()))
            {
                try
                {
                    await KeyExchangeAsync(cancellationToken);
                }
                catch (Exception ex)
                {
                    _initialKexComplete.TrySetException(ex);
                    _ready.TrySetException(ex);
                }
            }
        }

        private async Task KeyExchangeAsync(CancellationToken cancellationToken)
        {
            Memory<byte> sessionIdentifier = Memory<byte>.Empty;
            while (true)
            {
                // Start waiting for the server's KexInit.
                var serverKexInitTask = _client.ReadUntilAsync<KexInit>(cancellationToken);
                _ready.TrySetResult();

                // If this isn't the first key exchange, then just await until the server wants to start the exchange.
                if (!sessionIdentifier.IsEmpty)
                {
                    await serverKexInitTask.ConfigureAwait(false);
                }

                // Send our KexInit, and ensure the server's has also been received
                var clientKexInit = new KexInit();
                await _client.WriteMessageAsync(clientKexInit, cancellationToken).ConfigureAwait(false);
                var serverKexInit = await serverKexInitTask.ConfigureAwait(false);

                // Determine what the negotiated alogrithms are.
                var kexResult = new KexInitExchangeResult(clientKexInit, serverKexInit);
                var kexAlgorithm = KeyExchangeAlgorithm.Create(_client, kexResult);
                Task<KeyExchangeResult> exchangeTask = null;

                // Send the new keys. We need to begin waiting for SSH_MSG_NEWKEYS before we
                // the negotiated Key Exchange Algorithm completes, so the SSH_MSG_NEWKEYS
                // isn't missed. We also need to ensure that once we receive the SSH_MSG_NEWKEYS,
                // that we don't process any more messages until we've updated our ciphers. Finally
                // we need to send our own SSH_MSG_NEWKEYS and ensure no more messages are written
                // until our ciphers are updated.
                await _client.ReadUntilAsync(() =>
                {
                    exchangeTask = kexAlgorithm.ExchangeAsync(cancellationToken);
                    return Task.CompletedTask;
                },
                async m =>
                {
                    if (m.Type != MessageType.SSH_MSG_NEWKEYS || exchangeTask == null)
                    {
                        return false;
                    }

                    var (h, k) = await exchangeTask.ConfigureAwait(false);
                    sessionIdentifier = sessionIdentifier.IsEmpty ? h : sessionIdentifier;
                    var cryptoConfig = new CryptoConfig(sessionIdentifier, h, k, kexAlgorithm, kexResult);

                    await _client.WriteMessageAsync(new NewKeys(), cancellationToken).ConfigureAwait(false);
                    ApplyKeyExchange(cryptoConfig);
                    await _client.WriteMessageAsync(new NewKeysComplete(), cancellationToken).ConfigureAwait(false);
                    return true;
                }, cancellationToken).ConfigureAwait(false);

                // Lets callers know we've exchanged keys at least once!
                _initialKexComplete.TrySetResult();
            }
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
