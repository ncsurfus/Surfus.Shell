using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell.Authentication
{
    internal class PasswordAuth : IAuthMethod
    {
        private readonly string _password;

        internal PasswordAuth(string password)
        {
            _password = password;
        }

        public async Task SendRequestAsync(SshClient client, string username, CancellationToken cancellationToken)
        {
            await client.WriteMessageAsync(
                new UaRequest(username, "ssh-connection", "password", _password), cancellationToken)
                .ConfigureAwait(false);
        }

        public Task HandleMessage60Async(SshClient client, string username, MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            // Password auth does not use message 60.
            return Task.CompletedTask;
        }
    }
}
