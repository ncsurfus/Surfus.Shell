using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell.Authentication
{
    public class PasswordAuthenticationHandler : IAuthenticationHandler
    {
        private readonly SshClient _client;
        private readonly string _username;
        private readonly string _password;

        public PasswordAuthenticationHandler(SshClient client, string username, string password)
        {
            _client = client;
            _username = username;
            _password = password;
        }

        public async Task<bool> HandleAsync(ChannelReader<MessageEvent> channelReader, CancellationToken cancellationToken)
        {
            await _client
                .WriteMessageAsync(new UaRequest(_username, "ssh-connection", "password", _password), cancellationToken)
                .ConfigureAwait(false);

            var result = await channelReader.ReadAsync(cancellationToken);
            return result.Type switch
            {
                MessageType.SSH_MSG_USERAUTH_SUCCESS => true,
                MessageType.SSH_MSG_USERAUTH_FAILURE => false,
                _ => throw new SshUnexpectedMessage(MessageType.SSH_MSG_USERAUTH_SUCCESS)
            };
        }
    }
}
