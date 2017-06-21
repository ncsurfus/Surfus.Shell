using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;
using NLog;

namespace Surfus.Shell
{
    internal class SshAuthentication : IDisposable
    {

        // Fields
        private Logger _logger;
        private SshClient _client { get; }
        private readonly SemaphoreSlim _loginSemaphore = new SemaphoreSlim(1, 1);
        private State _loginState = State.Initial;
        private LoginType _loginType = LoginType.None;
        private string _username;
        private string _password;
        private Func<string, CancellationToken, Task<string>> _interactiveResponse;
        private bool _disposed;

        private TaskCompletionSource<UaInfoRequest> UserAuthInfoRequest = new TaskCompletionSource<UaInfoRequest>();

        public SshAuthentication(SshClient sshClient)
        {
            _client = sshClient;
            _logger = LogManager.GetLogger($"{_client.ConnectionInfo.Hostname} {_client.ConnectionInfo.Port}");
        }

        public async Task LoginAsync(string username, string password, CancellationToken cancellationToken)
        {
            await _loginSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if(_loginState != State.Initial)
            {
                throw new Exception("Cannot Login Twice...");
            }

            _username = username;
            _password = password;
            _loginType = LoginType.Password;

            await _client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _loginState = State.WaitingOnServiceAccept;

            _loginSemaphore.Release();
        }

        public async Task LoginAsync(string username, Func<string, CancellationToken, Task<string>> ResponseTask, CancellationToken cancellationToken)
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

        // Message Pumps
        public async Task ProcessMessageAsync(ServiceAccept message, CancellationToken cancellationToken)
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

        public async Task ProcessRequestFailureMessage( CancellationToken cancellationToken)
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

        public async Task ProcessMessageAsync(UaSuccess message, CancellationToken cancellationToken)
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

        public async Task<bool> ProcessMessageAsync(UaFailure message, CancellationToken cancellationToken)
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

        public async Task ProcessMessageAsync(UaInfoRequest message, CancellationToken cancellationToken)
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

        public void Close()
        {
            if(!_disposed)
            {
                _disposed = true;
                _password = null;
                _loginSemaphore.Dispose();
            }
        }

        public void Dispose()
        {
            Close();
        }

        internal enum State
        {
            Initial,
            WaitingOnServiceAccept,
            WaitingOnCredentialSuccessOrInteractive,
            WaitingOnCredentialSuccess,
            Completed,
            Failed
        }

        internal enum LoginType
        {
            None,
            Password,
            Interactive
        }
    }
}
