using System;
using System.Security.Cryptography;
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
        private readonly Func<ReadOnlyMemory<byte>, CancellationToken, Task<bool>>? _hostKeyCallback;
        private readonly SshAlgorithms _algorithms;
        private readonly SshMessageInbox _inbox = new();
        private readonly TaskCompletionSource _ready = new();
        private readonly TaskCompletionSource _initialKexComplete = new();
        private readonly Channel<Action> _newReadKeys = Channel.CreateUnbounded<Action>();

        internal SshKeyExchanger(
            SshConnectionInfo connectionInfo,
            Func<ReadOnlyMemory<byte>, CancellationToken, Task<bool>>? hostKeyCallback,
            SshAlgorithms algorithms
        )
        {
            _connectionInfo = connectionInfo;
            _hostKeyCallback = hostKeyCallback;
            _algorithms = algorithms;
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
                    _inbox.OnError(ex);
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

                var clientKexInit = new KexInit(_algorithms);
                await _inbox.SendAsync(clientKexInit, cancellationToken).ConfigureAwait(false);

                var kexResult = new KexInitExchangeResult(clientKexInit, serverKexInit);
                var kexContext = new KexContext(
                    _inbox,
                    _connectionInfo.ClientVersion,
                    _connectionInfo.ServerVersion,
                    _hostKeyCallback,
                    _algorithms
                );
                var kexAlgorithm = _algorithms.CreateKeyExchange(kexResult.KeyExchangeAlgorithm, kexContext, kexResult);

                var (h, k) = await kexAlgorithm.ExchangeAsync(cancellationToken).ConfigureAwait(false);

                _connectionInfo.ServerCertificate = kexContext.ServerCertificate;
                _connectionInfo.ServerCertificateSize = kexContext.ServerCertificateSize;
                sessionIdentifier = sessionIdentifier.IsEmpty ? h : sessionIdentifier;
                if (_connectionInfo.SessionIdentifier.IsEmpty)
                {
                    _connectionInfo.SessionIdentifier = sessionIdentifier.ToArray();
                }

                (await _inbox.ReadAsync(MessageType.SSH_MSG_NEWKEYS, cancellationToken).ConfigureAwait(false)).Dispose();

                // Send NewKeys with OLD crypto, then apply new write crypto
                await _inbox.SendAsync(new NewKeys(), cancellationToken).ConfigureAwait(false);
                try
                {
                    ApplyWriteCrypto(sessionIdentifier, h, k, kexAlgorithm, kexResult);
                }
                catch
                {
                    await _inbox.SendAsync(new NewKeysComplete(), cancellationToken).ConfigureAwait(false);
                    throw;
                }
                await _inbox.SendAsync(new NewKeysComplete(), cancellationToken).ConfigureAwait(false);

                // Hand read crypto to the read loop
                var readCrypto = CreateReadCrypto(sessionIdentifier, h, k, kexAlgorithm, kexResult);
                _newReadKeys.Writer.TryWrite(readCrypto);

                _initialKexComplete.TrySetResult();
            }
        }

        private async Task<KexInit> ReadKexInitAsync(CancellationToken cancellationToken)
        {
            using var msg = await _inbox.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (msg.Type != MessageType.SSH_MSG_KEXINIT)
            {
                throw new Exceptions.SshException($"Expected SSH_MSG_KEXINIT but received {msg.Type}.");
            }
            return new KexInit(msg.Packet);
        }

        private void ApplyWriteCrypto(
            Memory<byte> sessionId,
            Memory<byte> h,
            BigInt k,
            KeyExchangeAlgorithm kex,
            KexInitExchangeResult result
        )
        {
            var oldCompression = _connectionInfo.WriteCompressionAlgorithm;
            var oldCrypto = _connectionInfo.WriteCryptoAlgorithm;

            _connectionInfo.WriteCompressionAlgorithm = _algorithms.CreateCompression(result.CompressionClientToServer);
            _connectionInfo.WriteCryptoAlgorithm = _algorithms.CreateEncryption(result.EncryptionClientToServer);

            if (_connectionInfo.WriteCryptoAlgorithm.IsAead)
            {
                _connectionInfo.WriteMacAlgorithm = new NoMessageAuthentication();
            }
            else
            {
                _connectionInfo.WriteMacAlgorithm = _algorithms.CreateMac(result.MessageAuthenticationClientToServer);
            }

            oldCompression?.Dispose();
            oldCrypto?.Dispose();

            var iv = kex.GenerateKey(h, k, 'A', sessionId, _connectionInfo.WriteCryptoAlgorithm.InitializationVectorSize);
            var key = kex.GenerateKey(h, k, 'C', sessionId, _connectionInfo.WriteCryptoAlgorithm.KeySize);

            _connectionInfo.WriteCryptoAlgorithm.Initialize(iv, key);

            if (!_connectionInfo.WriteCryptoAlgorithm.IsAead)
            {
                var intKey = kex.GenerateKey(h, k, 'E', sessionId, _connectionInfo.WriteMacAlgorithm.KeySize);
                _connectionInfo.WriteMacAlgorithm.Initialize(intKey);
            }
        }

        private Action CreateReadCrypto(
            Memory<byte> sessionId,
            Memory<byte> h,
            BigInt k,
            KeyExchangeAlgorithm kex,
            KexInitExchangeResult result
        )
        {
            var readCompression = _algorithms.CreateCompression(result.CompressionServerToClient);
            var readCrypto = _algorithms.CreateEncryption(result.EncryptionServerToClient);
            MacAlgorithm readMac;

            var iv = kex.GenerateKey(h, k, 'B', sessionId, readCrypto.InitializationVectorSize);
            var key = kex.GenerateKey(h, k, 'D', sessionId, readCrypto.KeySize);

            readCrypto.Initialize(iv, key);

            if (readCrypto.IsAead)
            {
                readMac = new NoMessageAuthentication();
            }
            else
            {
                readMac = _algorithms.CreateMac(result.MessageAuthenticationServerToClient);
                var intKey = kex.GenerateKey(h, k, 'F', sessionId, readMac.KeySize);
                readMac.Initialize(intKey);
                CryptographicOperations.ZeroMemory(intKey);
            }

            CryptographicOperations.ZeroMemory(iv);
            CryptographicOperations.ZeroMemory(key);

            return () =>
            {
                var oldCompression = _connectionInfo.ReadCompressionAlgorithm;
                var oldCrypto = _connectionInfo.ReadCryptoAlgorithm;

                _connectionInfo.ReadCompressionAlgorithm = readCompression;
                _connectionInfo.ReadCryptoAlgorithm = readCrypto;
                _connectionInfo.ReadMacAlgorithm = readMac;

                oldCompression?.Dispose();
                oldCrypto?.Dispose();
            };
        }

        public Func<IClientMessage, CancellationToken, Task> OnSend
        {
            set => _inbox.OnSend = value;
        }

        public async ValueTask<bool> ProcessMessageAsync(MessageEvent messageEvent)
        {
            var id = (int)messageEvent.Type;
            if (id >= 20 && id <= 49)
            {
                await _inbox.DeliverAsync(messageEvent).ConfigureAwait(false);
                return true; // claimed — inbox consumer will dispose
            }
            return false;
        }

        public void OnError(Exception error) => _inbox.OnError(error);
    }
}
