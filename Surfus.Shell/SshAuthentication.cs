using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Authentication;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    /// <summary>
    /// Provides authentication methods
    /// </summary>
    internal class SshAuthentication
    {
        private readonly SshClient _client;
        private bool _serviceAccepted;

        internal SshAuthentication(SshClient client)
        {
            _client = client;
        }

        private static bool FilterMessage(MessageEvent message)
        {
            return message.Type switch
            {
                MessageType.SSH_MSG_USERAUTH_INFO_REQUEST
                or MessageType.SSH_MSG_USERAUTH_FAILURE
                or MessageType.SSH_MSG_USERAUTH_SUCCESS
                or MessageType.SSH_MSG_SERVICE_ACCEPT
                or MessageType.SSH_MSG_DISCONNECT
                    => true,
                _ => false,
            };
        }

        public async Task<bool> LoginAsync(IAuthenticationHandler handler, CancellationToken cancellationToken)
        {
            var channelReader = _client.RegisterMessageHandler(FilterMessage);
            try
            {
                if (!_serviceAccepted)
                {
                    await _client.WriteMessageAsync(new ServiceRequest("ssh-userauth"), cancellationToken).ConfigureAwait(false);
                    await channelReader.ReadAsync(MessageType.SSH_MSG_SERVICE_ACCEPT, cancellationToken).ConfigureAwait(false);
                    _serviceAccepted = true;
                }
                return await handler.HandleAsync(channelReader, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _client.DeregisterMessageHandler(channelReader);
            }
        }
    }
}
