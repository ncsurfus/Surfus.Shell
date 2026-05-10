using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    internal class SshMessageInbox : IDisposable
    {
        private readonly Channel<MessageEvent> _channel;

        internal SshMessageInbox(int capacity = 64)
        {
            _channel = Channel.CreateBounded<MessageEvent>(
                new BoundedChannelOptions(capacity) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true }
            );
        }

        internal Func<IClientMessage, CancellationToken, Task>? OnSend { get; set; }

        internal ValueTask DeliverAsync(MessageEvent message, CancellationToken cancellationToken = default) =>
            _channel.Writer.WriteAsync(message, cancellationToken);

        internal void Complete(Exception? error = null) => _channel.Writer.TryComplete(error);

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

        internal async ValueTask<MessageEvent> ReadAsync(MessageType expected, CancellationToken cancellationToken)
        {
            var msg = await ReadAsync(cancellationToken).ConfigureAwait(false);
            if (msg.Type != expected)
            {
                throw new SshException($"Expected {expected} but received {msg.Type}.");
            }
            return msg;
        }

        internal async ValueTask<T> ReadAsync<T>(CancellationToken cancellationToken)
            where T : class, IMessage
        {
            var msg = await ReadAsync(cancellationToken).ConfigureAwait(false);
            if (msg.Message is T typed)
            {
                return typed;
            }
            throw new SshException($"Expected {typeof(T).Name} but received {msg.Type}.");
        }

        internal Task SendAsync(IClientMessage message, CancellationToken cancellationToken)
        {
            if (OnSend == null)
            {
                throw new InvalidOperationException("No send handler registered on this inbox.");
            }
            return OnSend(message, cancellationToken);
        }

        public void Dispose() => Complete();
    }
}
