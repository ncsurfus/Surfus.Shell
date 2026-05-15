using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using Surfus.Shell.MessageViews.Channel;

namespace Surfus.Shell
{
    /// <summary>
    /// Represents an SSH channel with stdin/stdout/stderr streams.
    /// Messages are processed inline from the read loop — no background pump.
    /// </summary>
    public class SshChannel : IMessageHandler, IAsyncDisposable
    {
        private const int MaxPacketData = 32768;

        internal readonly SshMessageInbox Inbox = new();
        internal IDisposable? Registration { get; set; }

        // Remaining bytes the server allows us to send. Claimed atomically via CompareExchange in WriteDataAsync,
        // incremented via Interlocked.Add from the read loop (WindowAdjust).
        // Uses long to safely hold the full uint32 SSH window range.
        private long _sendWindow;

        // Bytes consumed by the reader since the last window adjust. Accumulated via Interlocked.Add;
        // flushed in FlushWindowAdjustAsync using a CompareExchange loop to avoid losing concurrent additions.
        private int _consumedBytes;

        private readonly Channel<bool> _sendWindowSignal = Channel.CreateBounded<bool>(1);

        // Queued TCSs for channel requests with WantReply=true. Completed in FIFO order matching SSH protocol guarantee.
        private readonly Queue<TaskCompletionSource<bool>> _pendingRequests = new();
        private volatile bool _opened;
        private int _closed; // 0 = open, 1 = closed. Used with Interlocked for atomic close.

        /// <summary>
        /// Number of consumed bytes that triggers sending a window adjust to the server.
        /// </summary>
        internal int WindowRefill { get; set; } = 50000;

        public uint ServerId { get; private set; }
        internal uint ClientId { get; }

        /// <summary>
        /// Whether the channel is still open.
        /// </summary>
        public bool IsOpen => _closed == 0 && _opened;

        /// <summary>
        /// The exit code returned by the remote process, or null if not yet received.
        /// </summary>
        public int? ExitCode { get; private set; }

        /// <summary>
        /// When true, stderr data is interleaved into StandardOutput.
        /// </summary>
        public bool CombineStderr { get; set; }

        /// <summary>Gets the writable stream for sending data to the remote process.</summary>
        public Stream StandardInput => Stdin;

        /// <summary>Gets the readable stream for the remote process's standard output.</summary>
        public Stream StandardOutput => Stdout;

        /// <summary>Gets the readable stream for the remote process's standard error.</summary>
        public Stream StandardError => Stderr;

        internal readonly ChannelStream Stdout;
        internal readonly ChannelStream Stderr;
        internal ChannelInputStream Stdin { get; private set; }

        internal SshChannel(uint channelId)
        {
            ClientId = channelId;
            Stdout = new ChannelStream { OnConsumed = OnBytesConsumedAsync };
            Stderr = new ChannelStream { OnConsumed = OnBytesConsumedAsync };
            Stdin = new ChannelInputStream(this);
        }

        /// <summary>
        /// Sends a channel request and optionally waits for the server's reply.
        /// </summary>
        /// <exception cref="SshException">Thrown if the server rejects the request.</exception>
        public async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            TaskCompletionSource<bool>? tcs = null;
            if (requestMessage.WantReply)
            {
                tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                lock (_pendingRequests)
                {
                    _pendingRequests.Enqueue(tcs);
                }
            }

            await Inbox.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);

            if (tcs == null)
            {
                return;
            }

            using var reg = cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken));
            var success = await tcs.Task.ConfigureAwait(false);
            if (!success)
            {
                throw new SshException("Server had channel request failure.");
            }
        }

        /// <summary>
        /// Sends a raw message on this channel.
        /// </summary>
        public async Task SendMessageAsync(IClientMessage message, CancellationToken cancellationToken)
        {
            await Inbox.SendAsync(message, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a channel close message to the server. Idempotent — only the first call sends.
        /// </summary>
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.CompareExchange(ref _closed, 1, 0) == 0)
            {
                _sendWindowSignal.Writer.TryComplete();
                await Inbox.SendAsync(new ChannelClose(ServerId), cancellationToken).ConfigureAwait(false);
            }
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _closed, 1);
            Stdout.Complete();
            Stderr.Complete();
            _sendWindowSignal.Writer.TryComplete();
            lock (_pendingRequests)
            {
                while (_pendingRequests.Count > 0)
                {
                    _pendingRequests.Dequeue().TrySetException(new SshException("Channel closed."));
                }
            }
            Registration?.Dispose();
            Inbox.Dispose();
            return ValueTask.CompletedTask;
        }

        internal async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            await Inbox.SendAsync(openMessage, cancellationToken).ConfigureAwait(false);

            while (true)
            {
                using var msg = await Inbox.ReadAsync(cancellationToken).ConfigureAwait(false);
                switch (msg.Type)
                {
                    case MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                        var confirm = new ChannelOpenConfirmationView(msg.Payload);
                        ServerId = confirm.SenderChannel;
                        Interlocked.Exchange(ref _sendWindow, confirm.InitialWindowSize);
                        _opened = true;
                        return;
                    case MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE:
                        throw new SshException("Server refused to open channel.");
                }
            }
        }

        internal async Task WriteDataAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                int claimed;
                while (true)
                {
                    if (!IsOpen)
                    {
                        throw new SshException("Channel closed.");
                    }

                    var current = Interlocked.Read(ref _sendWindow);
                    if (current == 0)
                    {
                        try
                        {
                            await _sendWindowSignal.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                        }
                        catch (ChannelClosedException)
                        {
                            throw new SshException("Channel closed.");
                        }
                        continue;
                    }

                    claimed = (int)Math.Min(Math.Min(buffer.Length - offset, current), MaxPacketData);
                    if (Interlocked.CompareExchange(ref _sendWindow, current - claimed, current) == current)
                    {
                        break;
                    }
                }

                // Re-check after claiming — if closed between claim and send, don't send.
                if (!IsOpen)
                {
                    throw new SshException("Channel closed.");
                }

                await Inbox.SendAsync(new ChannelData(ServerId, buffer.Slice(offset, claimed)), cancellationToken).ConfigureAwait(false);
                offset += claimed;
            }
        }

        /// <summary>Sends EOF to the server, signaling no more data will be written.</summary>
        internal async Task SendEofAsync(CancellationToken cancellationToken)
        {
            await Inbox.SendAsync(new ChannelEof(ServerId), cancellationToken).ConfigureAwait(false);
        }

        // IMessageHandler methods below are always called from the single-threaded SshClient read loop.

        Func<IClientMessage, CancellationToken, Task> IMessageHandler.OnSend
        {
            set => Inbox.OnSend = value;
        }

        async ValueTask<bool> IMessageHandler.ProcessMessageAsync(MessageEvent messageEvent)
        {
            // All channel messages have recipient channel as the first 4 bytes of payload
            var recipientChannel = new SpanReader(messageEvent.Payload).ReadUInt32();
            if (recipientChannel != ClientId) return false;

            if (!_opened)
            {
                await Inbox.DeliverAsync(messageEvent).ConfigureAwait(false);
                return true;
            }

            switch (messageEvent.Type)
            {
                case MessageType.SSH_MSG_CHANNEL_DATA:
                    Stdout.Push(messageEvent);
                    return true;

                case MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA:
                    (CombineStderr ? Stdout : Stderr).Push(messageEvent);
                    return true;

                case MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                {
                    var msg = new ChannelWindowAdjustView(messageEvent.Payload);
                    long current, updated;
                    do
                    {
                        current = Interlocked.Read(ref _sendWindow);
                        updated = Math.Min(current + msg.BytesToAdd, uint.MaxValue);
                    } while (Interlocked.CompareExchange(ref _sendWindow, updated, current) != current);
                    _sendWindowSignal.Writer.TryWrite(true);
                    return false;
                }

                case MessageType.SSH_MSG_CHANNEL_SUCCESS:
                    DequeueRequest(true);
                    return false;

                case MessageType.SSH_MSG_CHANNEL_FAILURE:
                    DequeueRequest(false);
                    return false;

                case MessageType.SSH_MSG_CHANNEL_REQUEST:
                {
                    var req = new ChannelRequestView(messageEvent.Payload);
                    if (req.RequestType.Is("exit-status"u8))
                        ExitCode = (int)req.ExitStatus;
                    return false;
                }

                case MessageType.SSH_MSG_CHANNEL_EOF:
                    Stdout.Complete();
                    Stderr.Complete();
                    return false;

                case MessageType.SSH_MSG_CHANNEL_CLOSE:
                    Interlocked.Exchange(ref _closed, 1);
                    Stdout.Complete();
                    Stderr.Complete();
                    _sendWindowSignal.Writer.TryComplete();
                    return false;

                default:
                    return false;
            }
        }

        void IMessageHandler.OnError(Exception error)
        {
            Inbox.OnError(error);
            Interlocked.Exchange(ref _closed, 1);
            Stdout.Complete(error);
            Stderr.Complete(error);
            _sendWindowSignal.Writer.TryComplete();
            lock (_pendingRequests)
            {
                while (_pendingRequests.Count > 0)
                {
                    _pendingRequests.Dequeue().TrySetException(error);
                }
            }
        }

        private void DequeueRequest(bool success)
        {
            TaskCompletionSource<bool> tcs;
            lock (_pendingRequests)
            {
                if (_pendingRequests.Count == 0)
                {
                    return;
                }
                tcs = _pendingRequests.Dequeue();
            }
            tcs.TrySetResult(success);
        }

        /// <summary>Accumulates consumed bytes and triggers a window adjust when the threshold is reached.</summary>
        private ValueTask OnBytesConsumedAsync(int count)
        {
            if (Interlocked.Add(ref _consumedBytes, count) >= WindowRefill)
            {
                return FlushWindowAdjustAsync();
            }
            return ValueTask.CompletedTask;
        }

        private async ValueTask FlushWindowAdjustAsync()
        {
            // Use CompareExchange loop to subtract only what we're claiming, so concurrent
            // additions from the other stream's OnConsumed are not lost.
            int toRefill;
            while (true)
            {
                var current = Volatile.Read(ref _consumedBytes);
                if (current < WindowRefill)
                {
                    return; // Another thread already flushed.
                }
                toRefill = current;
                if (Interlocked.CompareExchange(ref _consumedBytes, 0, current) == current)
                {
                    break;
                }
            }

            try
            {
                await Inbox.SendAsync(new ChannelWindowAdjust(ServerId, (uint)toRefill), CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // Restore so the next flush retries sending the adjust.
                Interlocked.Add(ref _consumedBytes, toRefill);
            }
        }
    }
}
