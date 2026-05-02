using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    /// <summary>
    /// Defines an SSH authentication method. Implementations handle the method-specific
    /// parts of the auth flow while SshAuthentication drives the state machine.
    /// </summary>
    internal interface IAuthMethod
    {
        /// <summary>
        /// Sends the initial authentication request after the ssh-userauth service is accepted.
        /// </summary>
        Task SendRequestAsync(SshClient client, string username, CancellationToken cancellationToken);

        /// <summary>
        /// Handles message type 60 (SSH_MSG_USERAUTH_PK_OK or SSH_MSG_USERAUTH_INFO_REQUEST).
        /// Returns the next state for the auth state machine.
        /// </summary>
        Task HandleMessage60Async(SshClient client, string username, MessageEvent messageEvent, CancellationToken cancellationToken);
    }
}
