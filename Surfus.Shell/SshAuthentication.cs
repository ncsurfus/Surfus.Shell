using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell
{
    /// <summary>
    /// Provides authentication methods
    /// </summary>
    internal class SshAuthentication : IDisposable
    {
        /// <summary>
        /// The SshClient that owns the channel.
        /// </summary>
        private SshClient Client { get; }

        /// <summary>
        /// The current state of authentication.
        /// </summary>
        private State _loginState = State.Initial;

        /// <summary>
        /// The type of login to be attempted.
        /// </summary>
        private LoginType _loginType = LoginType.None;

        /// <summary>
        /// The provided username.
        /// </summary>
        private string _username;

        /// <summary>
        /// The provided password.
        /// </summary>
        private string _password;

        /// <summary>
        /// The interactive response callback.
        /// </summary>
        private Func<string, CancellationToken, Task<string>> _interactiveResponse;

        /// <summary>
        /// The SSH agent client for publickey auth.
        /// </summary>
        private SshAgentClient _agent;

        /// <summary>
        /// The agent key to authenticate with.
        /// </summary>
        private SshAgentKey _agentKey;

        /// <summary>
        /// The disposed state of the channel.
        /// </summary>
        private bool _isDisposed;

        /// <summary>
        /// Provides authentication over SSH.
        /// </summary>
        /// <param name="sshClient"></param>
        internal SshAuthentication(SshClient sshClient)
        {
            Client = sshClient;
        }

        /// <summary>
        /// Logs in a user.
        /// </summary>
        /// <param name="username">The username to login with.</param>
        /// <param name="password">The password to login with.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task LoginAsync(string username, string password, CancellationToken cancellationToken)
        {
            if (_loginState != State.Initial)
            {
                throw new SshAuthenticationException("An authentication request was already attempted.");
            }

            _username = username;
            _password = password;
            _loginType = LoginType.Password;

            await Client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;

            await Client
                .ReadWhileAsync(() => _loginState != State.Completed && _loginState != State.Failed, cancellationToken)
                .ConfigureAwait(false);

            if (_loginState == State.Failed)
            {
                throw new SshInvalidCredentials();
            }
        }

        /// <summary>
        /// Logs in a user.
        /// </summary>
        /// <param name="username">The username to login with.</param>
        /// <param name="responseTask">The interactive callback.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task LoginAsync(
            string username,
            Func<string, CancellationToken, Task<string>> responseTask,
            CancellationToken cancellationToken
        )
        {
            if (_loginState != State.Initial)
            {
                throw new SshAuthenticationException("An authentication request was already attempted.");
            }

            _username = username;
            _interactiveResponse = responseTask;
            _loginType = LoginType.Interactive;
            await Client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;

            await Client
                .ReadWhileAsync(() => _loginState != State.Completed && _loginState != State.Failed, cancellationToken)
                .ConfigureAwait(false);

            if (_loginState == State.Failed)
            {
                throw new SshInvalidCredentials();
            }
        }

        /// <summary>
        /// Logs in a user by trying all keys from the SSH agent.
        /// </summary>
        internal async Task LoginAsync(string username, SshAgentClient agent, CancellationToken cancellationToken)
        {
            var keys = await agent.ListKeysAsync(cancellationToken).ConfigureAwait(false);
            if (keys.Count == 0)
            {
                throw new SshAuthenticationException("The SSH agent has no keys.");
            }

            if (_loginState != State.Initial)
            {
                throw new SshAuthenticationException("An authentication request was already attempted.");
            }

            _username = username;
            _agent = agent;
            _loginType = LoginType.PublicKey;

            await Client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;

            // Wait for ServiceAccept
            await Client
                .ReadWhileAsync(() => _loginState == State.WaitingOnServiceAccept, cancellationToken)
                .ConfigureAwait(false);

            // Try each key
            foreach (var key in keys)
            {
                _agentKey = key;
                _loginState = State.WaitingOnPublicKeyOk;

                // Send publickey query (has_signature=false)
                await Client
                    .WriteMessageAsync(new UaRequest(_username, "ssh-connection", key.KeyType, key.KeyBlob, null), cancellationToken)
                    .ConfigureAwait(false);

                await Client
                    .ReadWhileAsync(() => _loginState == State.WaitingOnPublicKeyOk || _loginState == State.WaitingOnCredentialSuccess, cancellationToken)
                    .ConfigureAwait(false);

                if (_loginState == State.Completed)
                {
                    return;
                }
                // State.Failed means this key was rejected, try the next one
            }

            throw new SshInvalidCredentials();
        }

        /// <summary>
        /// Logs in a user using a specific SSH agent key.
        /// </summary>
        internal async Task LoginAsync(string username, SshAgentClient agent, SshAgentKey key, CancellationToken cancellationToken)
        {
            if (_loginState != State.Initial)
            {
                throw new SshAuthenticationException("An authentication request was already attempted.");
            }

            _username = username;
            _agent = agent;
            _agentKey = key;
            _loginType = LoginType.PublicKey;

            await Client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;

            await Client
                .ReadWhileAsync(() => _loginState != State.Completed && _loginState != State.Failed, cancellationToken)
                .ConfigureAwait(false);

            if (_loginState == State.Failed)
            {
                throw new SshInvalidCredentials();
            }
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task ProcessMessageAsync(ServiceAccept message, CancellationToken cancellationToken)
        {
            if (_loginState != State.WaitingOnServiceAccept)
            {
                _loginState = State.Failed;
                throw new SshAuthenticationException(SshAuthenticationException.UnexpectedAuthenticationMessage);
            }

            if (_loginType == LoginType.Password)
            {
                await Client
                    .WriteMessageAsync(new UaRequest(_username, "ssh-connection", "password", _password), cancellationToken)
                    .ConfigureAwait(false);
                _password = null;
                _loginState = State.WaitingOnCredentialSuccess;
            }

            if (_loginType == LoginType.Interactive)
            {
                await Client
                    .WriteMessageAsync(new UaRequest(_username, "ssh-connection", "keyboard-interactive", (string)null, (string)null), cancellationToken)
                    .ConfigureAwait(false);
                _loginState = State.WaitingOnCredentialSuccessOrInteractive;
            }

            if (_loginType == LoginType.PublicKey)
            {
                if (_agentKey != null)
                {
                    // Single-key flow: send publickey query (has_signature=false)
                    await Client
                        .WriteMessageAsync(new UaRequest(_username, "ssh-connection", _agentKey.KeyType, _agentKey.KeyBlob, null), cancellationToken)
                        .ConfigureAwait(false);
                    _loginState = State.WaitingOnPublicKeyOk;
                }
                else
                {
                    // Try-all-keys flow: just mark service accepted, the loop sends queries
                    _loginState = State.WaitingOnPublicKeyOk;
                }
            }
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <returns></returns>
        internal void ProcessRequestFailureMessage()
        {
            _loginState = State.Failed;
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(UaSuccess message)
        {
            if (_loginState != State.WaitingOnCredentialSuccess && _loginState != State.WaitingOnCredentialSuccessOrInteractive && _loginState != State.WaitingOnPublicKeyOk)
            {
                _loginState = State.Failed;
                throw new SshAuthenticationException(SshAuthenticationException.UnexpectedAuthenticationMessage);
            }

            _loginState = State.Completed;
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(UaFailure message)
        {
            _loginState = State.Failed;
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        /// <summary>
        /// Handles message type 60, which is PK_OK for publickey auth or INFO_REQUEST for keyboard-interactive.
        /// </summary>
        internal async Task ProcessMessage60Async(MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            if (_loginState == State.WaitingOnPublicKeyOk)
            {
                // Message 60 = SSH_MSG_USERAUTH_PK_OK. Don't parse as UaInfoRequest.
                await ProcessPublicKeyOkAsync(cancellationToken).ConfigureAwait(false);
                return;
            }

            if (_loginState != State.WaitingOnCredentialSuccessOrInteractive)
            {
                _loginState = State.Failed;
                return;
            }

            // Message 60 = SSH_MSG_USERAUTH_INFO_REQUEST for keyboard-interactive.
            var message = messageEvent.Message as UaInfoRequest;
            var responses = new string[message.PromptNumber];
            for (var i = 0; i != responses.Length; i++)
            {
                responses[i] = await _interactiveResponse(message.Prompt[i], cancellationToken).ConfigureAwait(false);
            }

            await Client.WriteMessageAsync(new UaInfoResponse((uint)responses.Length, responses), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Handles SSH_MSG_USERAUTH_PK_OK by signing with the agent and sending the signed request.
        /// </summary>
        private async Task ProcessPublicKeyOkAsync(CancellationToken cancellationToken)
        {
            var sessionId = Client.ConnectionInfo.SessionIdentifier;

            // Build the data to sign per RFC 4252 section 7:
            // string    session identifier
            // byte      SSH_MSG_USERAUTH_REQUEST (50)
            // string    user name
            // string    service name ("ssh-connection")
            // string    "publickey"
            // boolean   TRUE
            // string    public key algorithm name
            // string    public key blob
            var dataSize = sessionId.GetBinaryStringSize()
                + 1
                + _username.GetStringSize()
                + "ssh-connection".GetAsciiStringSize()
                + "publickey".GetAsciiStringSize()
                + 1
                + _agentKey.KeyType.GetAsciiStringSize()
                + _agentKey.KeyBlob.GetBinaryStringSize();

            var dataWriter = new ByteWriter(dataSize);
            dataWriter.WriteBinaryString(sessionId);
            dataWriter.WriteByte(50); // SSH_MSG_USERAUTH_REQUEST
            dataWriter.WriteString(_username);
            dataWriter.WriteAsciiString("ssh-connection");
            dataWriter.WriteAsciiString("publickey");
            dataWriter.WriteByte(1); // TRUE
            dataWriter.WriteAsciiString(_agentKey.KeyType);
            dataWriter.WriteBinaryString(_agentKey.KeyBlob);

            var signature = await _agent.SignAsync(_agentKey.KeyBlob, dataWriter.Bytes, cancellationToken).ConfigureAwait(false);

            await Client
                .WriteMessageAsync(new UaRequest(_username, "ssh-connection", _agentKey.KeyType, _agentKey.KeyBlob, signature), cancellationToken)
                .ConfigureAwait(false);
            _loginState = State.WaitingOnCredentialSuccess;
        }

        /// <summary>
        /// Closes the SSH Authentication.
        /// </summary>
        internal void Close()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;
                _password = null;
            }
        }

        /// <summary>
        /// Disposes the SSH Authentication.
        /// </summary>
        public void Dispose()
        {
            Close();
        }

        /// <summary>
        /// The state of the authentication process.
        /// </summary>
        internal enum State
        {
            Initial,
            WaitingOnServiceAccept,
            WaitingOnCredentialSuccessOrInteractive,
            WaitingOnPublicKeyOk,
            WaitingOnCredentialSuccess,
            Completed,
            Failed
        }

        /// <summary>
        /// The SSH login Type.
        /// </summary>
        internal enum LoginType
        {
            None,
            Password,
            Interactive,
            PublicKey
        }
    }
}
