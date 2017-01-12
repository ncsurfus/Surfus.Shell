﻿using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.Exceptions;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.MessageAuthentication;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.KeyExchange;
using NLog;

namespace Surfus.Shell
{
    internal class SshKeyExchanger
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        private readonly SemaphoreSlim _clientKexInitSemaphore = new SemaphoreSlim(1);

        private KexInit _clientKexInit;

        // Message Sources
        internal TaskCompletionSource<KexInit> KexInitMessage = new TaskCompletionSource<KexInit>();
        internal TaskCompletionSource<NewKeys> NewKeysMessage = new TaskCompletionSource<NewKeys>();

        public SshKeyExchanger(SshClient client)
        {
            _client = client;
        }

        private SshClient _client { get; }

        // Key Exchange Informations
        public KeyExchangeAlgorithm KeyExchangeAlgorithm { get; private set; }
        public KexInitExchangeResult KeyExchangeResult { get; private set; }
        public byte[] SessionIdentifier { get; private set; }

        public async Task ExchangeKeysAsync(CancellationToken cancellationToken)
        {
            logger.Trace($"{_client.ConnectionInfo.Hostname}: Starting {nameof(ExchangeKeysAsync)}");

            try
            {
                while (!_client.IsFinished)
                {
                    // Wait for the server to send KexInit.
                    var serverKexInit = await KexInitMessage.Task;
                    logger.Debug($"{_client.ConnectionInfo.Hostname}: Received Server KexInit");

                    // Send our KexInit.
                    _clientKexInit = new KexInit();
                    await SshClientStaticThread.WriteMessageAsync(_client, _clientKexInit, cancellationToken);
                    logger.Debug($"{_client.ConnectionInfo.Hostname}: Sent Client KexInit");

                    // Compute KexInit Information.
                    KeyExchangeResult = new KexInitExchangeResult(_clientKexInit, serverKexInit);

                    // Conduct KeyExchange and wait for NewKeys
                    logger.Debug($"{_client.ConnectionInfo.Hostname}: Creating KeyExchangeAlgorithm");
                    KeyExchangeAlgorithm = KeyExchangeAlgorithm.Create(_client, KeyExchangeResult);

                    // Exchange
                    await KeyExchangeAlgorithm.ExchangeAsync();

                    // Send our NewKeys
                    logger.Debug($"{_client.ConnectionInfo.Hostname}: Waiting for Server NewKeys");
                    await SshClientStaticThread.WriteMessageAsync(_client, new NewKeys(), cancellationToken);

                    // Wait for New Keys before completing crypto.
                    var serverNewKeys = await NewKeysMessage.Task;

                    ApplyKeyExchange();

                    _client.ConnectTaskSource.TrySetResult(true);

                    // await SshClient.Log("Key Exchange: Restarting Loop");
                }
            }
            catch(Exception ex)
            {
                // Don't throw, exceptions get squashed on this thread. Relay to client
                _client.SetException(ex);
            }

            logger.Trace($"{_client.ConnectionInfo.Hostname}: Ending {nameof(ExchangeKeysAsync)}");
        }

        public void PumpKeyExchangeMessage(KexInit message)
        {
            KexInitMessage.SetResult(message);
        }

        public void PumpKeyExchangeMessage(NewKeys message)
        {
            NewKeysMessage.SetResult(message);
        }

        private void ApplyKeyExchange()
        {
            if (SessionIdentifier == null)
            {
                SessionIdentifier = KeyExchangeAlgorithm.H;
            }

            var connectionInfo = _client.ConnectionInfo;

            // Assign new Algorithms
            connectionInfo.ReadCompressionAlgorithm = CompressionAlgorithm.Create(KeyExchangeResult.CompressionServerToClient);
            connectionInfo.WriteCompressionAlgorithm = CompressionAlgorithm.Create(KeyExchangeResult.CompressionClientToServer);
            connectionInfo.ReadCryptoAlgorithm = CryptoAlgorithm.Create(KeyExchangeResult.EncryptionServerToClient);
            connectionInfo.WriteCryptoAlgorithm = CryptoAlgorithm.Create(KeyExchangeResult.EncryptionClientToServer);
            connectionInfo.ReadMacAlgorithm = MacAlgorithm.Create(KeyExchangeResult.MessageAuthenticationServerToClient);
            connectionInfo.WriteMacAlgorithm = MacAlgorithm.Create(KeyExchangeResult.MessageAuthenticationClientToServer);

            // Get Keys
            var writeIv = KeyExchangeAlgorithm.GenerateKey('A', SessionIdentifier, connectionInfo.WriteCryptoAlgorithm.InitializationVectorSize);
            var readIv = KeyExchangeAlgorithm.GenerateKey('B', SessionIdentifier, connectionInfo.ReadCryptoAlgorithm.InitializationVectorSize);
            var writeEncryptionKey = KeyExchangeAlgorithm.GenerateKey('C', SessionIdentifier, connectionInfo.WriteCryptoAlgorithm.KeySize);
            var readEncryptionKey = KeyExchangeAlgorithm.GenerateKey('D', SessionIdentifier, connectionInfo.ReadCryptoAlgorithm.KeySize);
            var writeIntegrityKey = KeyExchangeAlgorithm.GenerateKey('E', SessionIdentifier, connectionInfo.WriteMacAlgorithm.KeySize);
            var readIntegrityKey = KeyExchangeAlgorithm.GenerateKey('F', SessionIdentifier, connectionInfo.ReadMacAlgorithm.KeySize);

            // Initialize Keys
            connectionInfo.ReadCryptoAlgorithm.Initialize(readIv, readEncryptionKey);
            connectionInfo.WriteCryptoAlgorithm.Initialize(writeIv, writeEncryptionKey);
            connectionInfo.ReadMacAlgorithm.Initialize(readIntegrityKey);
            connectionInfo.WriteMacAlgorithm.Initialize(writeIntegrityKey);
        }
    }
}