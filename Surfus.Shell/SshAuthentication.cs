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
        private SshClient _client { get; }

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
        /// The disposed state of the channel.
        /// </summary>
        private bool _isDisposed;

        /// <summary>
        /// Provides authentication over SSH.
        /// </summary>
        /// <param name="sshClient"></param>
        internal SshAuthentication(SshClient sshClient)
        {
            _client = sshClient;
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
            if(_loginState != State.Initial)
            {
                throw new SshException("Cannot Login Twice...");
            }

            _username = username;
            _password = password;
            _loginType = LoginType.Password;

            await _client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;

            await _client.ReadUntilAsync(() => _loginState == State.Completed || _loginState == State.Failed, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Logs in a user.
        /// </summary>
        /// <param name="username">The username to login with.</param>
        /// <param name="ResponseTask">The interactive callback.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task LoginAsync(string username, Func<string, CancellationToken, Task<string>> ResponseTask, CancellationToken cancellationToken)
        {
            if (_loginState != State.Initial)
            {
                throw new Exception("Cannot Login Twice...");
            }

            _username = username;
            _interactiveResponse = ResponseTask;
            _loginType = LoginType.Interactive;
            await _client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task ProcessMessageAsync(ServiceAccept message, CancellationToken cancellationToken)
        {
            if(_loginState != State.WaitingOnServiceAccept)
            {
                _loginState = State.Failed;
                throw new SshException("Received unexpected login message.");
            }

            if(_loginType == LoginType.Password)
            {
                await _client.WriteMessageAsync(new UaRequest(_username, "ssh-connection", "password", _password), cancellationToken).ConfigureAwait(false);
                _password = null;
                _loginState = State.WaitingOnCredentialSuccess;
            }

            if (_loginType == LoginType.Interactive)
            {
                await _client.WriteMessageAsync(new UaRequest(_username, "ssh-connection", "keyboard-interactive", null, null), cancellationToken).ConfigureAwait(false);
                _loginState = State.WaitingOnCredentialSuccessOrInteractive;
            }
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessRequestFailureMessage()
        {
            _loginState = State.Failed;
            if (_loginState != State.WaitingOnServiceAccept)
            {
                throw new SshException("Received unexpected login message."); ;
            }
            throw new SshException("Server does not accept authentication.");
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(UaSuccess message)
        {
            if (_loginState != State.WaitingOnCredentialSuccess && _loginState != State.WaitingOnCredentialSuccessOrInteractive)
            {
                _loginState = State.Failed;
                throw new SshException("Received unexpected login message.");
            }

            _loginState = State.Completed;
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(UaFailure message)
        {
            if (_loginState != State.WaitingOnCredentialSuccess && _loginState != State.WaitingOnCredentialSuccessOrInteractive)
            {
                _loginState = State.Failed;
                throw new SshException("Received unexpected login message.");
            }
            throw new SshInvalidCredentials(_username);
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task ProcessMessageAsync(UaInfoRequest message, CancellationToken cancellationToken)
        {
            if (_loginState != State.WaitingOnCredentialSuccessOrInteractive)
            {
                _loginState = State.Failed;
                throw new SshException("Received unexpected login message."); ;
            }

            var responses = new string[message.PromptNumber];
            for (var i = 0; i != responses.Length; i++)
            {
                responses[i] = await _interactiveResponse(message.Prompt[i], cancellationToken).ConfigureAwait(false);
            }

            await _client.WriteMessageAsync(new UaInfoResponse((uint)responses.Length, responses), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Closes the SSH Authentication.
        /// </summary>
        internal void Close()
        {
            if(!_isDisposed)
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
            Interactive
        }
    }
}
