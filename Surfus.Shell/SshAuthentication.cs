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
    internal class SshAuthentication : IDisposable
    {
        private readonly SendMessageAsync _send;
        private readonly Func<byte[]> _getSessionIdentifier;
        private readonly SshMessageInbox _inbox = new();
        private bool _serviceAccepted;

        /// <summary>
        /// Called when the server sends a banner during authentication.
        /// </summary>
        internal Action<string> OnBanner { get; set; }

        internal SshAuthentication(SendMessageAsync send, Func<byte[]> getSessionIdentifier)
        {
            _send = send;
            _getSessionIdentifier = getSessionIdentifier;
        }

        internal async Task LoginAsync(string username, IAuthMethod method, CancellationToken cancellationToken)
        {
            await EnsureServiceAcceptedAsync(cancellationToken).ConfigureAwait(false);
            await AuthenticateWithMethodAsync(username, method, cancellationToken).ConfigureAwait(false);
        }

        internal async Task LoginAsync(string username, IReadOnlyList<IAuthMethod> methods, CancellationToken cancellationToken)
        {
            await EnsureServiceAcceptedAsync(cancellationToken).ConfigureAwait(false);

            for (var i = 0; i < methods.Count; i++)
            {
                var isLast = i == methods.Count - 1;
                try
                {
                    await AuthenticateWithMethodAsync(username, methods[i], cancellationToken).ConfigureAwait(false);
                    return;
                }
                catch (SshInvalidCredentials) when (!isLast)
                {
                }
            }
        }

        private async Task EnsureServiceAcceptedAsync(CancellationToken cancellationToken)
        {
            if (_serviceAccepted)
                return;

            await _send(new Messages.ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
            var msg = await ReadAuthMessageAsync(cancellationToken).ConfigureAwait(false);

            if (msg.Type != MessageType.SSH_MSG_SERVICE_ACCEPT)
                throw new SshAuthenticationException("The server does not support authentication.");

            _serviceAccepted = true;
        }

        private async Task AuthenticateWithMethodAsync(string username, IAuthMethod method, CancellationToken cancellationToken)
        {
            await method.SendRequestAsync(_send, username, cancellationToken).ConfigureAwait(false);

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
                        await method.HandleMessage60Async(_send, username, _getSessionIdentifier(), msg, cancellationToken).ConfigureAwait(false);
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

        internal void ProcessMessage(MessageEvent messageEvent) => _inbox.Deliver(messageEvent);

        public void Dispose() => _inbox.Dispose();
    }
}
