using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell.Authentication
{
    public delegate ValueTask<string> InteractiveCallback(string prompt, CancellationToken cancellationToken);

    public class InteractiveAuthenticationHandler : IAuthenticationHandler
    {
        private readonly SshClient _client;
        private readonly string _username;
        private readonly InteractiveCallback _interactiveCallback;

        public InteractiveAuthenticationHandler(SshClient client, string username, InteractiveCallback interactiveCallback)
        {
            _client = client;
            _username = username;
            _interactiveCallback = interactiveCallback;
        }

        public async Task<bool> HandleAsync(ChannelReader<MessageEvent> channelReader, CancellationToken cancellationToken)
        {
            // Request Keyboard Interactive
            await _client
                .WriteMessageAsync(new UaRequest(_username, "ssh-connection", "keyboard-interactive", null, null), cancellationToken)
                .ConfigureAwait(false);

            // The server could just authenticate us, or it may send one or more rounds of prompts.
            while (true)
            {
                var result = await channelReader.ReadAsync(cancellationToken).ConfigureAwait(false);
                switch (result.Type)
                {
                    case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST when result.Message is UaInfoRequest infoRequest:
                        var responses = new string[infoRequest.PromptNumber];
                        for (var i = 0; i != responses.Length; i++)
                        {
                            responses[i] = await _interactiveCallback(infoRequest.Prompt[i], cancellationToken).ConfigureAwait(false);
                        }
                        var infoResponse = new UaInfoResponse((uint)responses.Length, responses);
                        await _client.WriteMessageAsync(infoResponse, cancellationToken).ConfigureAwait(false);
                        break;
                    case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                        return true;
                    case MessageType.SSH_MSG_USERAUTH_FAILURE:
                        return false;
                    default:
                        throw new SshUnexpectedMessage(MessageType.SSH_MSG_USERAUTH_SUCCESS);
                }
            }
        }
    }
}
