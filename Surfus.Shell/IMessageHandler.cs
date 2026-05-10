using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    public interface IMessageHandler
    {
        Func<IClientMessage, CancellationToken, Task> OnSend { set; }
        ValueTask ProcessMessageAsync(MessageEvent messageEvent);
        void OnError(Exception error);
    }
}
