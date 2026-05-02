using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    /// <summary>
    /// A generic inbox for SSH messages. The read loop delivers messages
    /// via Deliver(), and consumers read them via ReadAsync(). If the read
    /// loop dies, Complete() faults all pending and future reads with the
    /// original exception.
    /// </summary>
    internal class SshMessageInbox : IDisposable
    {
        private readonly Channel<MessageEvent> _channel = Channel.CreateUnbounded<MessageEvent>();

        internal void Deliver(MessageEvent message) => _channel.Writer.TryWrite(message);

        internal void Complete(Exception error = null) => _channel.Writer.TryComplete(error);

        /// <summary>
        /// Error handler suitable for passing to RegisterMessageHandler.
        /// Completes the inbox so ReadAsync throws the original exception.
        /// </summary>
        internal void OnError(Exception error) => Complete(error ?? new SshException("Connection closed."));

        internal async ValueTask<MessageEvent> ReadAsync(CancellationToken cancellationToken)
        {
            try
            {
                return await _channel.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException ex)
            {
                throw ex.InnerException ?? new SshException("Connection closed.");
            }
        }

        public void Dispose() => Complete();
    }
}
