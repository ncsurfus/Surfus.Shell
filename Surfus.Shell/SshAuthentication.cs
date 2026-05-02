using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Authentication;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell
{
    /// <summary>
    /// Drives the SSH authentication state machine. Auth-method-specific logic
    /// is delegated to an IAuthMethod implementation.
    /// </summary>
    internal class SshAuthentication : IDisposable
    {
        private readonly SshClient _client;
        private IAuthMethod _method;
        private string _username;
        private State _state = State.Initial;
        internal SshAuthentication(SshClient client)
        {
            _client = client;
        }

        /// <summary>
        /// Authenticates using a single auth method.
        /// </summary>
        internal async Task LoginAsync(string username, IAuthMethod method, CancellationToken cancellationToken)
        {
            _username = username;
            _method = method;

            await EnsureServiceAcceptedAsync(cancellationToken).ConfigureAwait(false);

            _state = State.WaitingOnResponse;
            await _method.SendRequestAsync(_client, _username, cancellationToken).ConfigureAwait(false);

            await _client
                .ReadWhileAsync(() => _state == State.WaitingOnResponse || _state == State.WaitingOnMessage60Response, cancellationToken)
                .ConfigureAwait(false);

            if (_state == State.Failed)
                throw new SshInvalidCredentials();
        }

        /// <summary>
        /// Authenticates by trying a list of auth methods in order until one succeeds.
        /// </summary>
        internal async Task LoginAsync(string username, IReadOnlyList<IAuthMethod> methods, CancellationToken cancellationToken)
        {
            _username = username;
            await EnsureServiceAcceptedAsync(cancellationToken).ConfigureAwait(false);

            foreach (var method in methods)
            {
                _method = method;
                _state = State.WaitingOnResponse;
                await method.SendRequestAsync(_client, _username, cancellationToken).ConfigureAwait(false);

                await _client
                    .ReadWhileAsync(() => _state == State.WaitingOnResponse || _state == State.WaitingOnMessage60Response, cancellationToken)
                    .ConfigureAwait(false);

                if (_state == State.Completed)
                    return;
            }

            throw new SshInvalidCredentials();
        }

        private async Task EnsureServiceAcceptedAsync(CancellationToken cancellationToken)
        {
            if (_client.ConnectionInfo.UserAuthServiceAccepted)
                return;

            await _client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            _state = State.WaitingOnServiceAccept;

            await _client
                .ReadWhileAsync(() => _state == State.WaitingOnServiceAccept, cancellationToken)
                .ConfigureAwait(false);

            if (_state == State.Failed)
                throw new SshAuthenticationException("The server does not support authentication.");
        }

        // --- Message handlers called by SshClient.ReadMessageAsync ---

        internal Task ProcessMessageAsync(ServiceAccept message, CancellationToken cancellationToken)
        {
            if (_state != State.WaitingOnServiceAccept)
            {
                _state = State.Failed;
                return Task.CompletedTask;
            }
            _client.ConnectionInfo.UserAuthServiceAccepted = true;
            _state = State.ServiceAccepted;
            return Task.CompletedTask;
        }

        internal void ProcessRequestFailureMessage() => _state = State.Failed;

        internal void ProcessMessageAsync(UaSuccess message) => _state = State.Completed;

        internal void ProcessMessageAsync(UaFailure message) => _state = State.Failed;

        internal async Task ProcessMessage60Async(MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            if (_state != State.WaitingOnResponse && _state != State.WaitingOnMessage60Response)
            {
                _state = State.Failed;
                return;
            }

            _state = State.WaitingOnMessage60Response;
            await _method.HandleMessage60Async(_client, _username, messageEvent, cancellationToken).ConfigureAwait(false);
            _state = State.WaitingOnResponse;
        }

        internal void Close() { }

        public void Dispose() { }

        internal enum State
        {
            Initial,
            WaitingOnServiceAccept,
            ServiceAccepted,
            WaitingOnResponse,
            WaitingOnMessage60Response,
            Completed,
            Failed
        }
    }
}
