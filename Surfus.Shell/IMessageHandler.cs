using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    public interface IMessageHandler
    {
        Func<IClientMessage, CancellationToken, Task> OnSend { set; }

        /// <summary>
        /// Processes a message. Returns true if this handler claims ownership of the message's
        /// buffer (via the lease). When claimed, no further handlers are called and the handler
        /// is responsible for disposing the lease.
        /// </summary>
        ValueTask<bool> ProcessMessageAsync(MessageEvent messageEvent);
        void OnError(Exception error);
    }
}
