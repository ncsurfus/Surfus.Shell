using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.Exceptions;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.MessageAuthentication;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell
{
    /// <summary>
    /// Listens for and begins the key exchange process.
    /// </summary>
    internal class SshKeyExchanger
    {
        /// <summary>
        /// Coordinates access into the key exchangers.
        /// </summary>
        private readonly SemaphoreSlim _sshKeyExchangeSemaphore = new SemaphoreSlim(1, 1);

        /// <summary>
        /// The state of the key exchange.
        /// </summary>
        private State _keyExchangeState = State.Initial;

        /// <summary>
        /// The kexinit we've sent to the server.
        /// </summary>
        private KexInit _clientKexInit;

        /// <summary>
        /// The SshClient we're performing the key exchange for.
        /// </summary>
        private SshClient _client;

        /// <summary>
        /// The key exchange algorithm.
        /// </summary>
        internal KeyExchangeAlgorithm KeyExchangeAlgorithm { get; private set; }

        /// <summary>
        /// The result of the KexInit packets.
        /// </summary>
        internal KexInitExchangeResult KeyExchangeResult { get; private set; }

        /// <summary>
        /// The session identifier.
        /// </summary>
        internal byte[] SessionIdentifier { get; private set; }

        /// <summary>
        /// Listens for and begins the key exchange process.
        /// </summary>
        /// <param name="client">The client that the key exchange will be performed for.</param>
        internal SshKeyExchanger(SshClient client)
        {
            _client = client;
        }

        /// <summary>
        /// Attempts to send a client KexInit packet. Will return false if we've already sent a client Kexinit process.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>If we sent the KexInit or not.</returns>
        internal async Task<bool> TrySendClientKexInitAsync(CancellationToken cancellationToken)
        {
            await _sshKeyExchangeSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if(_keyExchangeState == State.Initial)
            {
                _clientKexInit = new KexInit();
                await _client.WriteMessageAsync(_clientKexInit, cancellationToken).ConfigureAwait(false);
                _keyExchangeState = State.SentKexNeedKex;
                return true;
            }

            _sshKeyExchangeSemaphore.Release();
            return false;
        }

        /// <summary>
        /// Processes a KeyExchange message.
        /// </summary>
        /// <param name="message">The key exchange message.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task ProcessMessageAsync(MessageEvent message, CancellationToken cancellationToken)
        {
            await _sshKeyExchangeSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            switch (message.Type)
            {

                case MessageType.SSH_MSG_KEXINIT:
                    if (_keyExchangeState == State.Initial)
                    {
                        _clientKexInit = new KexInit();
                        await _client.WriteMessageAsync(_clientKexInit, cancellationToken).ConfigureAwait(false);
                        _keyExchangeState = State.WaitingOnKeyExchangeProtocol;
                    }
                    else if (_keyExchangeState == State.SentKexNeedKex)
                    {
                        await _client.WriteMessageAsync(_clientKexInit, cancellationToken).ConfigureAwait(false);
                        _keyExchangeState = State.WaitingOnKeyExchangeProtocol;
                    }
                    else
                    {
                        throw new SshException("Received unexpected key exchange message."); ;
                    }
                    KeyExchangeResult = new KexInitExchangeResult(_clientKexInit, message.Message as KexInit);
                    KeyExchangeAlgorithm = KeyExchangeAlgorithm.Create(_client, KeyExchangeResult);
                    await KeyExchangeAlgorithm.InitiateKeyExchangeAlgorithmAsync(cancellationToken).ConfigureAwait(false);
                    break;

                case MessageType.SSH_MSG_KEX_Exchange_30:
                case MessageType.SSH_MSG_KEX_Exchange_31:
                case MessageType.SSH_MSG_KEX_Exchange_32:
                case MessageType.SSH_MSG_KEX_Exchange_33:
                case MessageType.SSH_MSG_KEX_Exchange_34:
                    if (_keyExchangeState != State.WaitingOnKeyExchangeProtocol)
                    {
                        throw new SshException("Received unexpected key exchange message."); ;

                    }
                    await ApplyKeyExchangeAlgorithmMessageAsync(message, cancellationToken).ConfigureAwait(false);
                    break;

                case MessageType.SSH_MSG_NEWKEYS:
                    if (_keyExchangeState != State.WaitingOnNewKeys)
                    {
                        throw new SshException("Received unexpected key exchange message.");

                    }
                    await _client.WriteMessageAsync(new NewKeys(), cancellationToken).ConfigureAwait(false);
                    ApplyKeyExchange();
                    _keyExchangeState = State.Initial;
                    break;
            }
            _sshKeyExchangeSemaphore.Release();
        }

        /// <summary>
        /// Forwards a key exchange method to the key exchange protocol.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        private async Task ApplyKeyExchangeAlgorithmMessageAsync(MessageEvent message, CancellationToken cancellationToken)
        {
            switch (message.Type)
            {
                case MessageType.SSH_MSG_KEX_Exchange_30:
                    if(await KeyExchangeAlgorithm.ProcessMessage30Async(message, cancellationToken).ConfigureAwait(false))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_31:
                    if (await KeyExchangeAlgorithm.ProcessMessage31Async(message, cancellationToken).ConfigureAwait(false))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_32:
                    if (await KeyExchangeAlgorithm.ProcessMessage32Async(message, cancellationToken).ConfigureAwait(false))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_33:
                    if (await KeyExchangeAlgorithm.ProcessMessage33Async(message, cancellationToken).ConfigureAwait(false))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_34:
                    if (await KeyExchangeAlgorithm.ProcessMessage34Async(message, cancellationToken).ConfigureAwait(false))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
            }
        }

        /// <summary>
        /// Initializes the crypto algorithms.
        /// </summary>
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

        /// <summary>
        /// The states of the key exchange process.
        /// </summary>
        internal enum State
        {
            Initial,
            SentKexNeedKex,
            WaitingOnKeyExchangeProtocol,
            WaitingOnNewKeys
        }
    }
}
