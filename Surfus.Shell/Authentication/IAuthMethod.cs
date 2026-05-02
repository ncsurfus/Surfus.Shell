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
        /// Returns the initial authentication request message to send.
        /// </summary>
        Task<IClientMessage> CreateRequestAsync(string username, CancellationToken cancellationToken);

        /// <summary>
        /// Handles message type 60 and returns a response message to send, or null if no response.
        /// </summary>
        Task<IClientMessage> HandleMessage60Async(string username, byte[] sessionIdentifier, MessageEvent messageEvent, CancellationToken cancellationToken);
    }
}
