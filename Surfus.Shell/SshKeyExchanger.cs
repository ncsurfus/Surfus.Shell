using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Authentication;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.MessageAuthentication;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell
{
    internal class SshKeyExchanger : IMessageHandler
    {
        private readonly SshConnectionInfo _connectionInfo;
        private readonly Func<byte[], bool> _hostKeyCallback;
        private readonly SshMessageInbox _inbox = new();
        private readonly TaskCompletionSource _ready = new();
        private readonly TaskCompletionSource _initialKexComplete = new();
        private readonly Channel<Action> _newReadKeys = Channel.CreateUnbounded<Action>();

        internal SshKeyExchanger(SshConnectionInfo connectionInfo, Func<byte[], bool> hostKeyCallback)
        {
            _connectionInfo = connectionInfo;
            _hostKeyCallback = hostKeyCallback;
        }

        internal Task Ready => _ready.Task;
        internal Task InitialKeyExchangeComplete => _initialKexComplete.Task;

        /// <summary>
        /// Called by the read loop after delivering SSH_MSG_NEWKEYS.
        /// Blocks until write crypto is applied and returns an action to apply read crypto.
        /// </summary>
        internal async Task<Action> GetNewReadKeysAsync(CancellationToken cancellationToken)
        {
            return await _newReadKeys.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }

        internal async Task HandleKeyExchangeAsync(CancellationToken cancellationToken)
        {
            using (cancellationToken.Register(() => _ready.TrySetCanceled()))
            using (cancellationToken.Register(() => _initialKexComplete.TrySetCanceled()))
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
            _ready.TrySetResult();

            while (true)
            {
                var serverKexInit = await ReadKexInitAsync(cancellationToken).ConfigureAwait(false);

                var clientKexInit = new KexInit();
                await _inbox.SendAsync(clientKexInit, cancellationToken).ConfigureAwait(false);

                var kexResult = new KexInitExchangeResult(clientKexInit, serverKexInit);
                var kexContext = new KexContext(
                    _inbox,
                    _connectionInfo.ClientVersion, _connectionInfo.ServerVersion,
                    _hostKeyCallback);
                var kexAlgorithm = KeyExchangeAlgorithm.Create(kexContext, kexResult);

                var (h, k) = await kexAlgorithm.ExchangeAsync(cancellationToken).ConfigureAwait(false);

                _connectionInfo.ServerCertificate = kexContext.ServerCertificate;
                _connectionInfo.ServerCertificateSize = kexContext.ServerCertificateSize;
                sessionIdentifier = sessionIdentifier.IsEmpty ? h : sessionIdentifier;
                _connectionInfo.SessionIdentifier ??= sessionIdentifier.ToArray();

                await _inbox.ReadAsync(MessageType.SSH_MSG_NEWKEYS, cancellationToken).ConfigureAwait(false);

                // Send NewKeys with OLD crypto, then apply new write crypto
                await _inbox.SendAsync(new NewKeys(), cancellationToken).ConfigureAwait(false);
                ApplyWriteCrypto(sessionIdentifier, h, k, kexAlgorithm, kexResult);
                await _inbox.SendAsync(new NewKeysComplete(), cancellationToken).ConfigureAwait(false);

                // Hand read crypto to the read loop
                var readCrypto = CreateReadCrypto(sessionIdentifier, h, k, kexAlgorithm, kexResult);
                _newReadKeys.Writer.TryWrite(readCrypto);

                _initialKexComplete.TrySetResult();
            }
        }

        private async Task<KexInit> ReadKexInitAsync(CancellationToken cancellationToken)
        {
            return await _inbox.ReadAsync<KexInit>(cancellationToken).ConfigureAwait(false);
        }

        private void ApplyWriteCrypto(Memory<byte> sessionId, Memory<byte> h, BigInt k, KeyExchangeAlgorithm kex, KexInitExchangeResult result)
        {
            _connectionInfo.WriteCompressionAlgorithm = CompressionAlgorithm.Create(result.CompressionClientToServer);
            _connectionInfo.WriteCryptoAlgorithm = CryptoAlgorithm.Create(result.EncryptionClientToServer);
            _connectionInfo.WriteMacAlgorithm = MacAlgorithm.Create(result.MessageAuthenticationClientToServer);

            var iv = kex.GenerateKey(h, k, 'A', sessionId, _connectionInfo.WriteCryptoAlgorithm.InitializationVectorSize);
            var key = kex.GenerateKey(h, k, 'C', sessionId, _connectionInfo.WriteCryptoAlgorithm.KeySize);
            var intKey = kex.GenerateKey(h, k, 'E', sessionId, _connectionInfo.WriteMacAlgorithm.KeySize);

            _connectionInfo.WriteCryptoAlgorithm.Initialize(iv, key);
            _connectionInfo.WriteMacAlgorithm.Initialize(intKey);
        }

        private Action CreateReadCrypto(Memory<byte> sessionId, Memory<byte> h, BigInt k, KeyExchangeAlgorithm kex, KexInitExchangeResult result)
        {
            var readCompression = CompressionAlgorithm.Create(result.CompressionServerToClient);
            var readCrypto = CryptoAlgorithm.Create(result.EncryptionServerToClient);
            var readMac = MacAlgorithm.Create(result.MessageAuthenticationServerToClient);

            var iv = kex.GenerateKey(h, k, 'B', sessionId, readCrypto.InitializationVectorSize);
            var key = kex.GenerateKey(h, k, 'D', sessionId, readCrypto.KeySize);
            var intKey = kex.GenerateKey(h, k, 'F', sessionId, readMac.KeySize);

            readCrypto.Initialize(iv, key);
            readMac.Initialize(intKey);

            return () =>
            {
                _connectionInfo.ReadCompressionAlgorithm = readCompression;
                _connectionInfo.ReadCryptoAlgorithm = readCrypto;
                _connectionInfo.ReadMacAlgorithm = readMac;
            };
        }

        public Func<IClientMessage, CancellationToken, Task> OnSend { set => _inbox.OnSend = value; }

        public void ProcessMessage(MessageEvent messageEvent)
        {
            var id = (int)messageEvent.Type;
            if (id >= 20 && id <= 49)
                _inbox.Deliver(messageEvent);
        }
        public void OnError(Exception error) => _inbox.OnError(error);
    }
}
