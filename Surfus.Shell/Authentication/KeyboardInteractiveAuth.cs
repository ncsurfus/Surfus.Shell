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

        internal KeyboardInteractiveAuth(Func<string, CancellationToken, Task<string>> responseCallback) =>
            _responseCallback = responseCallback;

        public Task<IClientMessage> CreateRequestAsync(string username, CancellationToken cancellationToken) =>
            Task.FromResult<IClientMessage>(new UaRequest(username, "ssh-connection", "keyboard-interactive", (string?)null, (string?)null));

        public async Task<IClientMessage?> HandleMessage60Async(
            string username,
            ReadOnlyMemory<byte> sessionIdentifier,
            MessageEvent messageEvent,
            CancellationToken cancellationToken
        )
        {
            var infoReq = new MessageViews.UserAuth.UserAuthInfoRequestView(messageEvent.Payload);
            var count = (int)infoReq.PromptCount;
            var prompts = new string[count];
            var echo = new bool[count];
            infoReq.ReadPrompts(prompts, echo);

            var responses = new string[count];
            for (var i = 0; i < count; i++)
            {
                responses[i] = await _responseCallback(prompts[i], cancellationToken).ConfigureAwait(false);
            }
            return new UaInfoResponse((uint)responses.Length, responses);
        }
    }
}
