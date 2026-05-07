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
    internal class SshAuthentication : IMessageHandler, IDisposable
    {
        private readonly Func<ReadOnlyMemory<byte>> _getSessionIdentifier;
        private readonly SshMessageInbox _inbox = new();
        private bool _serviceAccepted;

        /// <summary>
        /// Called when the server sends a banner during authentication.
        /// </summary>
        internal Action<string> OnBanner { get; set; }

        internal SshAuthentication(Func<ReadOnlyMemory<byte>> getSessionIdentifier)
        {
            _getSessionIdentifier = getSessionIdentifier;
        }

        internal async Task LoginAsync(string username, IAuthMethod method, CancellationToken cancellationToken)
        {
            await EnsureServiceAcceptedAsync(cancellationToken).ConfigureAwait(false);
            await AuthenticateWithMethodAsync(username, method, cancellationToken).ConfigureAwait(false);
        }

        internal async Task LoginAsync(string username, IReadOnlyList<IAuthMethod> methods, CancellationToken cancellationToken)
        {
            if (methods == null || methods.Count == 0)
            {
                throw new ArgumentException("At least one authentication method must be provided.", nameof(methods));
            }

            await EnsureServiceAcceptedAsync(cancellationToken).ConfigureAwait(false);

            for (var i = 0; i < methods.Count; i++)
            {
                var isLast = i == methods.Count - 1;
                try
                {
                    await AuthenticateWithMethodAsync(username, methods[i], cancellationToken).ConfigureAwait(false);
                    return;
                }
                catch (SshInvalidCredentials) when (!isLast) { }
            }
        }

        private async Task EnsureServiceAcceptedAsync(CancellationToken cancellationToken)
        {
            if (_serviceAccepted)
            {
                return;
            }

            await _inbox.SendAsync(new Messages.ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            var msg = await ReadAuthMessageAsync(cancellationToken).ConfigureAwait(false);

            if (msg.Type != MessageType.SSH_MSG_SERVICE_ACCEPT)
            {
                throw new SshAuthenticationException("The server does not support authentication.");
            }

            _serviceAccepted = true;
        }

        private async Task AuthenticateWithMethodAsync(string username, IAuthMethod method, CancellationToken cancellationToken)
        {
            var request = await method.CreateRequestAsync(username, cancellationToken).ConfigureAwait(false);
            await _inbox.SendAsync(request, cancellationToken).ConfigureAwait(false);

            while (true)
            {
                var msg = await ReadAuthMessageAsync(cancellationToken).ConfigureAwait(false);

                switch (msg.Type)
                {
                    case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                        return;

                    case MessageType.SSH_MSG_USERAUTH_FAILURE:
                        throw new SshInvalidCredentials();

                    case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                        var response = await method
                            .HandleMessage60Async(username, _getSessionIdentifier(), msg, cancellationToken)
                            .ConfigureAwait(false);
                        if (response != null)
                        {
                            await _inbox.SendAsync(response, cancellationToken).ConfigureAwait(false);
                        }
                        continue;

                    default:
                        throw new SshException($"Unexpected message during authentication: {msg.Type}");
                }
            }
        }

        /// <summary>
        /// Reads the next message from the inbox, skipping banners and
        /// throwing on disconnect.
        /// </summary>
        private async Task<MessageEvent> ReadAuthMessageAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                var msg = await _inbox.ReadAsync(cancellationToken).ConfigureAwait(false);

                if (msg.Type == MessageType.SSH_MSG_USERAUTH_BANNER)
                {
                    OnBanner?.Invoke((msg.Message as UaBanner)?.Message);
                    continue;
                }

                if (msg.Type == MessageType.SSH_MSG_DISCONNECT)
                {
                    var disconnect = (Disconnect)msg.Message;
                    throw new SshDisconnectException(disconnect.Reason);
                }

                return msg;
            }
        }

        public Func<IClientMessage, CancellationToken, Task> OnSend
        {
            set => _inbox.OnSend = value;
        }

        public ValueTask ProcessMessageAsync(MessageEvent messageEvent)
        {
            var id = (int)messageEvent.Type;
            // Only deliver service accept (6), disconnect (1), and auth-range messages (50-79)
            if (id == 6 || id == 1 || (id >= 50 && id <= 79))
            {
                return _inbox.DeliverAsync(messageEvent);
            }
            return ValueTask.CompletedTask;
        }

        public void OnError(Exception error) => _inbox.OnError(error);

        public void Dispose() => _inbox.Dispose();
    }
}
