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
    public class SshKeyExchanger
    {
        private readonly SendMessageAsync _send;
        private readonly SshConnectionInfo _connectionInfo;
        private readonly Func<byte[], bool> _hostKeyCallback;
        private readonly SshMessageInbox _inbox = new();
        private readonly TaskCompletionSource _ready = new();
        private readonly TaskCompletionSource _initialKexComplete = new();
        private readonly Channel<Action> _newReadKeys = Channel.CreateUnbounded<Action>();

        internal SshKeyExchanger(SendMessageAsync send, SshConnectionInfo connectionInfo, Func<byte[], bool> hostKeyCallback)
        {
            _send = send;
            _connectionInfo = connectionInfo;
            _hostKeyCallback = hostKeyCallback;
        }

        public Task Ready => _ready.Task;
        public Task InitialKeyExchangeComplete => _initialKexComplete.Task;

        /// <summary>
        /// Called by the read loop after delivering SSH_MSG_NEWKEYS.
        /// Blocks until write crypto is applied and returns an action to apply read crypto.
        /// </summary>
        internal async Task<Action> GetNewReadKeysAsync(CancellationToken cancellationToken)
        {
            return await _newReadKeys.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }

        public async Task HandleKeyExchangeAsync(CancellationToken cancellationToken)
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
                await _send(clientKexInit, cancellationToken).ConfigureAwait(false);

                var kexResult = new KexInitExchangeResult(clientKexInit, serverKexInit);
                var kexContext = new KexContext(
                    _send, _inbox,
                    _connectionInfo.ClientVersion, _connectionInfo.ServerVersion,
                    _hostKeyCallback);
                var kexAlgorithm = KeyExchangeAlgorithm.Create(kexContext, kexResult);

                var (h, k) = await kexAlgorithm.ExchangeAsync(cancellationToken).ConfigureAwait(false);

                _connectionInfo.ServerCertificate = kexContext.ServerCertificate;
                _connectionInfo.ServerCertificateSize = kexContext.ServerCertificateSize;
                sessionIdentifier = sessionIdentifier.IsEmpty ? h : sessionIdentifier;
                _connectionInfo.SessionIdentifier ??= sessionIdentifier.ToArray();

                var newKeysMsg = await _inbox.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (newKeysMsg.Type != MessageType.SSH_MSG_NEWKEYS)
                    throw new Exceptions.SshException($"Expected SSH_MSG_NEWKEYS but got {newKeysMsg.Type}");

                // Send NewKeys with OLD crypto, then apply new write crypto
                await _send(new NewKeys(), cancellationToken).ConfigureAwait(false);
                ApplyWriteCrypto(sessionIdentifier, h, k, kexAlgorithm, kexResult);
                await _send(new NewKeysComplete(), cancellationToken).ConfigureAwait(false);

                // Hand read crypto to the read loop
                var readCrypto = CreateReadCrypto(sessionIdentifier, h, k, kexAlgorithm, kexResult);
                _newReadKeys.Writer.TryWrite(readCrypto);

                _initialKexComplete.TrySetResult();
            }
        }

        private async Task<KexInit> ReadKexInitAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                var msg = await _inbox.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (msg.Type == MessageType.SSH_MSG_KEXINIT)
                    return (KexInit)msg.Message;
            }
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

        internal void ProcessMessage(MessageEvent messageEvent) => _inbox.Deliver(messageEvent);
        internal void OnError(Exception error) => _inbox.OnError(error);
    }
}
