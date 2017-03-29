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
        // Fields
        private Logger _logger = LogManager.GetCurrentClassLogger();
        private readonly SemaphoreSlim _sshKeyExchangeSemaphore = new SemaphoreSlim(1, 1);
        private State _keyExchangeState = State.Initial;
        private KexInit _clientKexInit;
        private SshClient _client;

        // Properties
        internal KeyExchangeAlgorithm KeyExchangeAlgorithm { get; private set; }
        internal KexInitExchangeResult KeyExchangeResult { get; private set; }
        internal byte[] SessionIdentifier { get; private set; }

        internal SshKeyExchanger(SshClient client)
        {
            _client = client;
            _logger = LogManager.GetLogger($"{_client.ConnectionInfo.Hostname} {_client.ConnectionInfo.Port}");
        }

        // Attempts to send a client kex init packet if we're in the expected state.
        internal async Task<bool> TrySendClientKexInitAsync(CancellationToken cancellationToken)
        {
            await _sshKeyExchangeSemaphore.WaitAsync(cancellationToken);

            if(_keyExchangeState == State.Initial)
            {
                _clientKexInit = new KexInit();
                await _client.WriteMessageAsync(_clientKexInit, cancellationToken);
                _keyExchangeState = State.SentKexNeedKex;
                return true;
            }

            _sshKeyExchangeSemaphore.Release();
            return false;
        }

        // ApplyKeyExchangeMessageAsync is called from the SshClient's ReadMessage method to move the state forward.
        internal async Task ProcessMessageAsync(MessageEvent message, CancellationToken cancellationToken)
        {
            await _sshKeyExchangeSemaphore.WaitAsync(cancellationToken);
            switch (message.Type)
            {

                case MessageType.SSH_MSG_KEXINIT:
                    if (_keyExchangeState == State.Initial)
                    {
                        _clientKexInit = new KexInit();
                        await _client.WriteMessageAsync(_clientKexInit, cancellationToken);
                        _keyExchangeState = State.WaitingOnKeyExchangeProtocol;
                    }
                    else if (_keyExchangeState == State.SentKexNeedKex)
                    {
                        await _client.WriteMessageAsync(_clientKexInit, cancellationToken);
                        _keyExchangeState = State.WaitingOnKeyExchangeProtocol;
                    }
                    else
                    {
                        throw new SshException("Received unexpected key exchange message."); ;
                    }
                    KeyExchangeResult = new KexInitExchangeResult(_clientKexInit, message.Message as KexInit);
                    KeyExchangeAlgorithm = KeyExchangeAlgorithm.Create(_client, KeyExchangeResult);
                    await KeyExchangeAlgorithm.InitiateKeyExchangeAlgorithmAsync(cancellationToken);
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
                    await ApplyKeyExchangeAlgorithmMessageAsync(message, cancellationToken);
                    break;

                case MessageType.SSH_MSG_NEWKEYS:
                    if (_keyExchangeState != State.WaitingOnNewKeys)
                    {
                        throw new SshException("Received unexpected key exchange message.");

                    }
                    await _client.WriteMessageAsync(new NewKeys(), cancellationToken);
                    ApplyKeyExchange();
                    _keyExchangeState = State.Initial;
                    break;
            }
            _sshKeyExchangeSemaphore.Release();
        }

        // ApplyKeyExchangeAlgorithmAsync will forward a message to the Key Exchange Message algorithm
        private async Task ApplyKeyExchangeAlgorithmMessageAsync(MessageEvent message, CancellationToken cancellationToken)
        {
            switch (message.Type)
            {
                case MessageType.SSH_MSG_KEX_Exchange_30:
                    if(await KeyExchangeAlgorithm.SendKeyExchangeMessage30Async(message, cancellationToken))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_31:
                    if (await KeyExchangeAlgorithm.SendKeyExchangeMessage31Async(message, cancellationToken))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_32:
                    if (await KeyExchangeAlgorithm.SendKeyExchangeMessage32Async(message, cancellationToken))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_33:
                    if (await KeyExchangeAlgorithm.SendKeyExchangeMessage33Async(message, cancellationToken))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
                case MessageType.SSH_MSG_KEX_Exchange_34:
                    if (await KeyExchangeAlgorithm.SendKeyExchangeMessage34Async(message, cancellationToken))
                    {
                        _keyExchangeState = State.WaitingOnNewKeys;
                    }
                    break;
            }
        }

        // ApplyKeyExchange is called from ApplyKeyExchangeMessageAsync to compute the Key Exchange and Crypto information.
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

        // State represents the current state of the key exchange
        internal enum State
        {
            Initial,
            SentKexNeedKex,
            WaitingOnKeyExchangeProtocol,
            WaitingOnNewKeys
        }
    }
}
