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
        /// Used to coordinate async access.
        /// </summary>
        private readonly SemaphoreSlim _loginSemaphore = new SemaphoreSlim(1, 1);

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
        /// The Task Compeletion Source to be set once the server sends the UserAuthInfoRequest response.
        /// </summary>
        private TaskCompletionSource<UaInfoRequest> UserAuthInfoRequest = new TaskCompletionSource<UaInfoRequest>();

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
            await _loginSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if(_loginState != State.Initial)
            {
                throw new SshException("Cannot Login Twice...");
            }

            _username = username;
            _password = password;
            _loginType = LoginType.Password;

            await _client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;

            _loginSemaphore.Release();
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
            await _loginSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_loginState != State.Initial)
            {
                throw new Exception("Cannot Login Twice...");
            }

            _username = username;
            _interactiveResponse = ResponseTask;
            _loginType = LoginType.Interactive;
            await _client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;

            _loginSemaphore.Release();
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task ProcessMessageAsync(ServiceAccept message, CancellationToken cancellationToken)
        {
            await _loginSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if(_loginState != State.WaitingOnServiceAccept)
            {
                _loginState = State.Failed;
                _loginSemaphore.Release();
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

            _loginSemaphore.Release();
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task ProcessRequestFailureMessage(CancellationToken cancellationToken)
        {
            await _loginSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
           

            if (_loginState != State.WaitingOnServiceAccept)
            { _loginState = State.Failed;
                _loginSemaphore.Release();
                throw new SshException("Received unexpected login message."); ;
            }

            _loginState = State.Failed;
            _loginSemaphore.Release();
            throw new SshException("Server does not accept authentication.");
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task ProcessMessageAsync(UaSuccess message, CancellationToken cancellationToken)
        {
            await _loginSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_loginState != State.WaitingOnCredentialSuccess && _loginState != State.WaitingOnCredentialSuccessOrInteractive)
            {
                _loginState = State.Failed;
                _loginSemaphore.Release();
                throw new SshException("Received unexpected login message.");
            }

            _loginState = State.Completed;

            // SshClient will properly set the task completion source once this returns...

            _loginSemaphore.Release();
        }

        /// <summary>
        /// Processes an authentication message sent by the server.
        /// </summary>
        /// <param name="message">The message sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task<bool> ProcessMessageAsync(UaFailure message, CancellationToken cancellationToken)
        {
            await _loginSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_loginState != State.WaitingOnCredentialSuccess && _loginState != State.WaitingOnCredentialSuccessOrInteractive)
            {
                _loginState = State.Failed;
                _loginSemaphore.Release();
                throw new SshException("Received unexpected login message.");
            }
           
            _loginSemaphore.Release();
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
            await _loginSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_loginState != State.WaitingOnCredentialSuccessOrInteractive)
            {
                _loginState = State.Failed;
                _loginSemaphore.Release();
                throw new SshException("Received unexpected login message."); ;
            }

            var responses = new string[message.PromptNumber];
            for (var i = 0; i != responses.Length; i++)
            {
                responses[i] = await _interactiveResponse(message.Prompt[i], cancellationToken).ConfigureAwait(false);
            }

            await _client.WriteMessageAsync(new UaInfoResponse((uint)responses.Length, responses), cancellationToken).ConfigureAwait(false);

            _loginSemaphore.Release();

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
                _loginSemaphore.Dispose();
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
