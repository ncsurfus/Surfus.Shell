using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using Surfus.Shell.Messages.Channel.Requests;

namespace Surfus.Shell
{
    /// <summary>
    /// Represents an SSH channel with stdin/stdout/stderr streams.
    /// Obtain via <see cref="SshClient.CreateChannelAsync"/>.
    /// </summary>
    public class SshChannel : IMessageHandler, IAsyncDisposable
    {
        internal readonly SshMessageInbox Inbox = new();
        internal IDisposable Registration { get; set; }

        internal int WindowRefill { get; set; } = 50000;
        private int _sendWindow;
        internal int SendWindow
        {
            get => Interlocked.CompareExchange(ref _sendWindow, 0, 0);
            set => Interlocked.Exchange(ref _sendWindow, value);
        }
        internal int ReceiveWindow { get; set; }
        internal uint ServerId { get; set; }
        internal uint ClientId { get; }

        /// <summary>
        /// Whether the channel is still open.
        /// </summary>
        public bool IsOpen { get; private set; }

        /// <summary>
        /// The exit code returned by the remote process, or null if not yet received.
        /// </summary>
        public int? ExitCode { get; private set; }

        /// <summary>
        /// When true, stderr data is interleaved into StandardOutput.
        /// Must be set before data starts flowing.
        /// </summary>
        public bool CombineStderr { get; init; }

        public Stream StandardInput => Stdin;
        public Stream StandardOutput => Stdout;
        public Stream StandardError => Stderr;

        internal readonly ChannelStream Stdout = new();
        internal readonly ChannelStream Stderr = new();
        internal ChannelInputStream Stdin { get; private set; }

        private int _consumedBytes;
        private readonly CancellationTokenSource _pumpCts = new();
        private Task _pumpTask;

        private readonly Queue<TaskCompletionSource<bool>> _pendingRequests = new();
        private readonly SemaphoreSlim _sendWindowAvailable = new(0);
        private volatile bool _pumpRunning;

        /// <summary>
        /// Bounded channel for data messages (ChannelData, ChannelExtendedData).
        /// Back-pressure here is by design: the SSH receive window (50KB) limits in-flight data to 2-3 packets, so 64 slots is generous. If the consumer stalls, blocking the read loop is correct — it prevents unbounded memory growth and signals the server to stop sending.
        /// </summary>
        private readonly Channel<MessageEvent> _dataInbox = Channel.CreateBounded<MessageEvent>(
            new BoundedChannelOptions(64) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true }
        );

        /// <summary>
        /// Unbounded channel for control messages (WindowAdjust, Success, Failure, EOF, Close, etc.).
        /// These must never block the read loop.
        /// </summary>
        private readonly Channel<MessageEvent> _controlInbox = Channel.CreateUnbounded<MessageEvent>(
            new UnboundedChannelOptions { SingleReader = true }
        );

        internal SshChannel(uint channelId)
        {
            ClientId = channelId;
            Stdin = new ChannelInputStream(this);
            Stdout.OnConsumed = OnBytesConsumed;
            Stderr.OnConsumed = OnBytesConsumed;
        }

        public async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            TaskCompletionSource<bool> tcs = null;
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
                return;

            using var reg = cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken));
            var success = await tcs.Task.ConfigureAwait(false);

            if (!success)
                throw new SshException("Server had channel request failure.");
        }

        public async Task SendMessageAsync(IClientMessage message, CancellationToken cancellationToken)
        {
            await Inbox.SendAsync(message, cancellationToken).ConfigureAwait(false);
        }

        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (IsOpen)
            {
                await Inbox.SendAsync(new ChannelClose(ServerId), cancellationToken).ConfigureAwait(false);
                IsOpen = false;
            }
        }

        public async ValueTask DisposeAsync()
        {
            _pumpCts.Cancel();
            _dataInbox.Writer.TryComplete();
            _controlInbox.Writer.TryComplete();
            if (_pumpTask != null)
            {
                try
                {
                    await _pumpTask.ConfigureAwait(false);
                }
                catch { }
            }
            Stdout.Complete();
            Stderr.Complete();
            Registration?.Dispose();
            Inbox.Dispose();
            _pumpCts.Dispose();
            _sendWindowAvailable.Dispose();
        }

        internal async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            ReceiveWindow = (int)openMessage.InitialWindowSize;
            await Inbox.SendAsync(openMessage, cancellationToken).ConfigureAwait(false);

            // Before pump starts, read from the legacy inbox for the open handshake.
            while (true)
            {
                var msg = await Inbox.ReadAsync(cancellationToken).ConfigureAwait(false);
                switch (msg.Message)
                {
                    case ChannelOpenConfirmation confirm:
                        ServerId = confirm.SenderChannel;
                        SendWindow = (int)confirm.InitialWindowSize;
                        IsOpen = true;
                        StartMessagePump();
                        return;
                    case ChannelOpenFailure:
                        throw new SshException("Server refused to open channel.");
                }
            }
        }

        internal async Task WriteDataAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            var totalBytesLeft = buffer.Length;
            var offset = 0;
            while (totalBytesLeft > 0)
            {
                while (SendWindow == 0)
                {
                    if (!IsOpen)
                        throw new SshException("Channel closed.");
                    await _sendWindowAvailable.WaitAsync(cancellationToken).ConfigureAwait(false);
                }

                var chunkSize = Math.Min(totalBytesLeft, SendWindow);
                var chunk = buffer.Slice(offset, chunkSize).ToArray();
                await Inbox.SendAsync(new ChannelData(ServerId, chunk), cancellationToken).ConfigureAwait(false);
                Interlocked.Add(ref _sendWindow, -chunkSize);
                totalBytesLeft -= chunkSize;
                offset += chunkSize;
            }
        }

        internal async Task SendEofAsync(CancellationToken cancellationToken)
        {
            await Inbox.SendAsync(new ChannelEof(ServerId), cancellationToken).ConfigureAwait(false);
        }

        // --- Message pump ---

        private void StartMessagePump()
        {
            _pumpRunning = true;
            _pumpTask = Task.Run(RunPumpAsync);
        }

        private async Task RunPumpAsync()
        {
            var ct = _pumpCts.Token;
            try
            {
                while (IsOpen)
                {
                    // Always drain all available control messages first (non-blocking).
                    while (_controlInbox.Reader.TryRead(out var controlMsg))
                        ProcessControlMessage(controlMsg);

                    // Try to read a data message (non-blocking).
                    if (_dataInbox.Reader.TryRead(out var dataMsg))
                    {
                        ProcessDataMessage(dataMsg);
                        continue;
                    }

                    // Nothing available — wait for either channel to have data.
                    // TODO: Task.WhenAny allocates a Task per iteration causing GC pressure.
                    // A future optimization could use a custom awaiter or ValueTask-based approach.
                    var controlReady = _controlInbox.Reader.WaitToReadAsync(ct).AsTask();
                    var dataReady = _dataInbox.Reader.WaitToReadAsync(ct).AsTask();
                    await Task.WhenAny(controlReady, dataReady).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (SshException) { }
            catch (ChannelClosedException) { }
            catch (Exception) { }
            finally
            {
                Stdout.Complete();
                Stderr.Complete();
                lock (_pendingRequests)
                {
                    while (_pendingRequests.Count > 0)
                        _pendingRequests.Dequeue().TrySetException(new SshException("Channel closed."));
                }
                _sendWindowAvailable.Release();
            }
        }

        private void ProcessControlMessage(MessageEvent msg)
        {
            switch (msg.Message)
            {
                case ChannelWindowAdjust adjust:
                    Interlocked.Add(ref _sendWindow, (int)adjust.BytesToAdd);
                    _sendWindowAvailable.Release();
                    break;

                case ChannelSuccess:
                    DequeueRequest(true);
                    break;

                case ChannelFailure:
                    DequeueRequest(false);
                    break;

                case ChannelRequestExitStatus exitStatus:
                    ExitCode = (int)exitStatus.ExitStatus;
                    break;

                case ChannelEof:
                    Stdout.Complete();
                    Stderr.Complete();
                    break;

                case ChannelClose:
                    IsOpen = false;
                    Stdout.Complete();
                    Stderr.Complete();
                    break;
            }
        }

        private void ProcessDataMessage(MessageEvent msg)
        {
            switch (msg.Message)
            {
                case ChannelData data:
                    HandleReceiveWindow(data.Data.Length);
                    Stdout.Push(data.Data.Span);
                    break;

                case ChannelExtendedData extData:
                    HandleReceiveWindow(extData.Data.Length);
                    if (CombineStderr)
                        Stdout.Push(extData.Data.Span);
                    else
                        Stderr.Push(extData.Data.Span);
                    break;
            }
        }

        private void HandleReceiveWindow(int dataLength)
        {
            ReceiveWindow -= Math.Min(dataLength, ReceiveWindow);
        }

        private void DequeueRequest(bool success)
        {
            TaskCompletionSource<bool> tcs;
            lock (_pendingRequests)
            {
                if (_pendingRequests.Count == 0)
                    return;
                tcs = _pendingRequests.Dequeue();
            }
            tcs.TrySetResult(success);
        }

        private void OnBytesConsumed(int count)
        {
            var newValue = Interlocked.Add(ref _consumedBytes, count);
            if (newValue >= WindowRefill)
            {
                var toRefill = Interlocked.Exchange(ref _consumedBytes, 0);
                if (toRefill > 0)
                {
                    _ = SendWindowAdjustAsync(toRefill);
                }
            }
        }

        private async Task SendWindowAdjustAsync(int toRefill)
        {
            try
            {
                await Inbox.SendAsync(new ChannelWindowAdjust(ServerId, (uint)toRefill), CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // Best-effort: if sending fails, the channel will stall but not crash.
            }
        }

        // --- IMessageHandler (called from SshClient read loop) ---

        Func<IClientMessage, CancellationToken, Task> IMessageHandler.OnSend
        {
            set => Inbox.OnSend = value;
        }

        async ValueTask IMessageHandler.ProcessMessageAsync(MessageEvent messageEvent)
        {
            if (messageEvent.Message is not IChannelRecipient r || r.RecipientChannel != ClientId)
                return;

            if (!_pumpRunning)
            {
                // During open handshake, route to the legacy inbox.
                await Inbox.DeliverAsync(messageEvent).ConfigureAwait(false);
                return;
            }

            // Route data messages to bounded data inbox, everything else to unbounded control inbox.
            switch (messageEvent.Message)
            {
                case ChannelData:
                case ChannelExtendedData:
                    await _dataInbox.Writer.WriteAsync(messageEvent).ConfigureAwait(false);
                    break;

                default:
                    _controlInbox.Writer.TryWrite(messageEvent);
                    break;
            }
        }

        void IMessageHandler.OnError(Exception error)
        {
            Inbox.OnError(error);
            _dataInbox.Writer.TryComplete(error);
            _controlInbox.Writer.TryComplete(error);
        }
    }
}
