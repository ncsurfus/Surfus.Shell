using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell.Authentication
{
    internal class PasswordAuth : IAuthMethod
    {
        private readonly string _password;

        internal PasswordAuth(string password) => _password = password;

        public Task<IClientMessage> CreateRequestAsync(string username, CancellationToken cancellationToken)
            => Task.FromResult<IClientMessage>(new UaRequest(username, "ssh-connection", "password", _password));

        public Task<IClientMessage> HandleMessage60Async(string username, byte[] sessionIdentifier, MessageEvent messageEvent, CancellationToken cancellationToken)
            => Task.FromResult<IClientMessage>(null);
    }
}
