using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell.Authentication
{
    internal class KeyboardInteractiveAuth : IAuthMethod
    {
        private readonly Func<string, CancellationToken, Task<string>> _responseCallback;

        internal KeyboardInteractiveAuth(Func<string, CancellationToken, Task<string>> responseCallback)
            => _responseCallback = responseCallback;

        public Task<IClientMessage> CreateRequestAsync(string username, CancellationToken cancellationToken)
            => Task.FromResult<IClientMessage>(new UaRequest(username, "ssh-connection", "keyboard-interactive", (string)null, (string)null));

        public async Task<IClientMessage> HandleMessage60Async(string username, byte[] sessionIdentifier, MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            var message = (UaInfoRequest)messageEvent.Message;
            var responses = new string[message.PromptNumber];
            for (var i = 0; i < responses.Length; i++)
                responses[i] = await _responseCallback(message.Prompt[i], cancellationToken).ConfigureAwait(false);
            return new UaInfoResponse((uint)responses.Length, responses);
        }
    }
}
