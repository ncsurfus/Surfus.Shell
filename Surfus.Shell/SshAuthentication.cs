using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell
{
    internal class SshAuthentication
    {
        // Message Sources
        internal TaskCompletionSource<ServiceAccept> ServiceAcceptMessage = new TaskCompletionSource<ServiceAccept>();
        internal TaskCompletionSource<UaSuccess> UserAuthSuccessMessage = new TaskCompletionSource<UaSuccess>();
        internal TaskCompletionSource<UaInfoRequest> UserAuthInfoRequest = new TaskCompletionSource<UaInfoRequest>();

        public SshClient SshClient { get; }

        public SshAuthentication(SshClient sshclient)
        {
            SshClient = sshclient;
        }

        private async Task CommonLoginAsync(CancellationToken cancellationToken)
        {
            if (!ServiceAcceptMessage.Task.IsCompleted)
            {
                await SshClientStaticThread.WriteMessageAsync(SshClient, new ServiceRequest("ssh-userauth"), cancellationToken);
            }

            await ServiceAcceptMessage.Task;
        }

        public async Task LoginAsync(string username, string password, CancellationToken cancellationToken)
        {
            UserAuthSuccessMessage = new TaskCompletionSource<UaSuccess>();
            await CommonLoginAsync(cancellationToken);

            await SshClientStaticThread.WriteMessageAsync(SshClient, new UaRequest(username, "ssh-connection", "password", password), cancellationToken);
            await UserAuthSuccessMessage.Task;

            SshClient.LoginTaskSource.TrySetResult(true);
        }

        public async Task LoginInteractiveAsync(string username, Func<string, CancellationToken, Task<string>> ResponseTask, CancellationToken cancellationToken)
        {
            UserAuthSuccessMessage = new TaskCompletionSource<UaSuccess>();
            UserAuthInfoRequest = new TaskCompletionSource<UaInfoRequest>();
            await CommonLoginAsync(cancellationToken);

            await SshClientStaticThread.WriteMessageAsync(SshClient, new UaRequest(username, "ssh-connection", "keyboard-interactive", null, null), cancellationToken);

            while (!cancellationToken.IsCancellationRequested && !SshClient.InternalCancellation.IsCancellationRequested)
            {
                var responseMessage = await Task.WhenAny(UserAuthSuccessMessage.Task, UserAuthInfoRequest.Task);

                if (responseMessage == UserAuthSuccessMessage.Task)
                {
                    await UserAuthSuccessMessage.Task;
                    SshClient.LoginTaskSource.TrySetResult(true);
                    return;
                }
                if (responseMessage == UserAuthInfoRequest.Task)
                {
                    var uaInfoRequest = await UserAuthInfoRequest.Task;
                    UserAuthInfoRequest = new TaskCompletionSource<UaInfoRequest>();

                    var responses = new string[uaInfoRequest.PromptNumber];
                    for (var i = 0; i != responses.Length; i++)
                    {
                        responses[i] = await ResponseTask(uaInfoRequest.Prompt[i], cancellationToken);
                    }

                    await SshClientStaticThread.WriteMessageAsync(SshClient, new UaInfoResponse((uint)responses.Length, responses), cancellationToken);
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            SshClient.InternalCancellation.Token.ThrowIfCancellationRequested();
        }

        // Message Pumps
        public void SendMessage(ServiceAccept message)
        {
            ServiceAcceptMessage.SetResult(message);
        }

        public void SendRequestFailureMessage()
        {
            ServiceAcceptMessage.TrySetException(new SshException("Server does not accept authentication"));
        }

        public void SendMessage(UaSuccess message)
        {
            UserAuthSuccessMessage.TrySetResult(message);
        }

        public void SendMessage(UaFailure message)
        {
            UserAuthSuccessMessage.TrySetException(new SshException("Server rejected credentials"));
        }

        public void SendMessage(UaInfoRequest message)
        {
            UserAuthInfoRequest.SetResult(message);
        }
    }
}
