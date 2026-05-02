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

        public async Task SendRequestAsync(SendMessageAsync send, string username, CancellationToken cancellationToken)
        {
            await send(new UaRequest(username, "ssh-connection", "password", _password), cancellationToken).ConfigureAwait(false);
        }

        public Task HandleMessage60Async(SendMessageAsync send, string username, byte[] sessionIdentifier, MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
