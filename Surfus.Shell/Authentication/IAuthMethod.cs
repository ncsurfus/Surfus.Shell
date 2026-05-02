using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Authentication
{
    /// <summary>
    /// A delegate for sending SSH messages.
    /// </summary>
    internal delegate Task SendMessageAsync(IClientMessage message, CancellationToken cancellationToken);

    /// <summary>
    /// Defines an SSH authentication method.
    /// </summary>
    internal interface IAuthMethod
    {
        /// <summary>
        /// Sends the initial authentication request.
        /// </summary>
        Task SendRequestAsync(SendMessageAsync send, string username, CancellationToken cancellationToken);

        /// <summary>
        /// Handles message type 60 (PK_OK or INFO_REQUEST depending on auth method).
        /// </summary>
        Task HandleMessage60Async(SendMessageAsync send, string username, byte[] sessionIdentifier, MessageEvent messageEvent, CancellationToken cancellationToken);
    }
}
