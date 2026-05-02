using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    internal interface IMessageHandler
    {
        Func<IClientMessage, CancellationToken, Task> OnSend { set; }
        void ProcessMessage(MessageEvent messageEvent);
        void OnError(Exception error);
    }
}
