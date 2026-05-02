using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    /// <summary>
    /// A generic inbox for SSH messages. The read loop delivers messages
    /// via Deliver(), and consumers read them via ReadAsync().
    /// </summary>
    internal class SshMessageInbox : IDisposable
    {
        private readonly Channel<MessageEvent> _channel = Channel.CreateUnbounded<MessageEvent>();

        internal void Deliver(MessageEvent message) => _channel.Writer.TryWrite(message);

        internal ValueTask<MessageEvent> ReadAsync(CancellationToken cancellationToken)
            => _channel.Reader.ReadAsync(cancellationToken);

        public void Dispose() => _channel.Writer.TryComplete();
    }
}
