using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;

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
        internal int SendWindow { get; set; }
        internal int ReceiveWindow { get; set; }
        internal uint ServerId { get; set; }
        internal uint ClientId { get; }

        /// <summary>
        /// Whether the channel is still open.
        /// </summary>
        public bool IsOpen { get; private set; }

        /// <summary>
        /// When true, stderr data is interleaved into StandardOutput.
        /// Must be set before data starts flowing.
        /// </summary>
        public bool CombineStderr { get; set; }

        /// <summary>
        /// Writable stream to send data to the remote side.
        /// Dispose to send EOF.
        /// </summary>
        public Stream StandardInput => Stdin;

        /// <summary>
        /// Readable stream of stdout data from the remote side.
        /// </summary>
        public Stream StandardOutput => Stdout;

        /// <summary>
        /// Readable stream of stderr data from the remote side.
        /// </summary>
        public Stream StandardError => Stderr;

        internal readonly ChannelStream Stdout = new();
        internal readonly ChannelStream Stderr = new();
        internal ChannelInputStream Stdin { get; private set; }

        private int _consumedBytes;
        private readonly CancellationTokenSource _pumpCts = new();
        private Task _pumpTask;

        private TaskCompletionSource<bool> _pendingRequest;
        private TaskCompletionSource _sendWindowAvailable = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal SshChannel(uint channelId)
        {
            ClientId = channelId;
            Stdin = new ChannelInputStream(this);
            Stdout.OnConsumed = OnBytesConsumed;
            Stderr.OnConsumed = OnBytesConsumed;
        }

        /// <summary>
        /// Sends a channel request and waits for the server's success/failure reply.
        /// </summary>
        public async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            _pendingRequest = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            await Inbox.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);

            using var reg = cancellationToken.Register(() => _pendingRequest.TrySetCanceled(cancellationToken));
            var success = await _pendingRequest.Task.ConfigureAwait(false);
            _pendingRequest = null;

            if (!success)
                throw new SshException("Server had channel request failure.");
        }

        /// <summary>
        /// Sends an arbitrary message on this channel.
        /// </summary>
        public async Task SendMessageAsync(IClientMessage message, CancellationToken cancellationToken)
        {
            await Inbox.SendAsync(message, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Closes the channel.
        /// </summary>
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (IsOpen)
            {
                await Inbox.SendAsync(new ChannelClose(ServerId), cancellationToken).ConfigureAwait(false);
                IsOpen = false;
            }
        }

        /// <summary>
        /// Disposes the channel, stopping the message pump and completing streams.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            _pumpCts.Cancel();
            if (_pumpTask != null)
            {
                try { await _pumpTask.ConfigureAwait(false); } catch { }
            }
            Stdout.Complete();
            Stderr.Complete();
            Registration?.Dispose();
            Inbox.Dispose();
            _pumpCts.Dispose();
        }

        // --- Internal: framework plumbing ---

        internal async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            ReceiveWindow = (int)openMessage.InitialWindowSize;
            await Inbox.SendAsync(openMessage, cancellationToken).ConfigureAwait(false);

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

        internal async Task WriteDataAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            var totalBytesLeft = buffer.Length;
            var offset = 0;
            while (totalBytesLeft > 0)
            {
                while (SendWindow == 0)
                {
                    if (!IsOpen) throw new SshException("Channel closed.");
                    await _sendWindowAvailable.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                    if (SendWindow == 0)
                        _sendWindowAvailable = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                }

                var chunkSize = Math.Min(totalBytesLeft, SendWindow);
                var chunk = buffer;
                if (chunkSize < buffer.Length)
                {
                    chunk = new byte[chunkSize];
                    Array.Copy(buffer, offset, chunk, 0, chunkSize);
                }
                await Inbox.SendAsync(new ChannelData(ServerId, chunk), cancellationToken).ConfigureAwait(false);
                SendWindow -= chunkSize;
                totalBytesLeft -= chunkSize;
                offset += chunkSize;
            }
        }

        internal async Task SendEofAsync(CancellationToken cancellationToken)
        {
            await Inbox.SendAsync(new ChannelEof(ServerId), cancellationToken).ConfigureAwait(false);
        }

        private void StartMessagePump()
        {
            _pumpTask = Task.Run(async () =>
            {
                try
                {
                    while (IsOpen)
                    {
                        var msg = await Inbox.ReadAsync(_pumpCts.Token).ConfigureAwait(false);
                        ProcessMessage(msg);
                    }
                }
                catch (OperationCanceledException) { }
                catch (SshException) { }
                finally
                {
                    Stdout.Complete();
                    Stderr.Complete();
                    _pendingRequest?.TrySetException(new SshException("Channel closed."));
                    _sendWindowAvailable.TrySetResult();
                }
            });
        }

        private void OnBytesConsumed(int count)
        {
            _consumedBytes += count;
            if (_consumedBytes >= WindowRefill)
            {
                var toRefill = _consumedBytes;
                _consumedBytes = 0;
                _ = Inbox.SendAsync(new ChannelWindowAdjust(ServerId, (uint)toRefill), CancellationToken.None);
            }
        }

        private void ProcessMessage(MessageEvent msg)
        {
            switch (msg.Message)
            {
                case ChannelWindowAdjust adjust:
                    SendWindow += (int)adjust.BytesToAdd;
                    _sendWindowAvailable.TrySetResult();
                    break;

                case ChannelData data:
                    HandleReceiveWindow(data.Data);
                    Stdout.Push(data.Data, 0, data.Data.Length);
                    break;

                case ChannelExtendedData extData:
                    HandleReceiveWindow(extData.Data);
                    if (CombineStderr)
                        Stdout.Push(extData.Data, 0, extData.Data.Length);
                    else
                        Stderr.Push(extData.Data, 0, extData.Data.Length);
                    break;

                case ChannelSuccess:
                    _pendingRequest?.TrySetResult(true);
                    break;

                case ChannelFailure:
                    _pendingRequest?.TrySetResult(false);
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

        private void HandleReceiveWindow(byte[] data)
        {
            ReceiveWindow -= Math.Min(data.Length, ReceiveWindow);
        }

        Func<IClientMessage, CancellationToken, Task> IMessageHandler.OnSend { set => Inbox.OnSend = value; }

        async ValueTask IMessageHandler.ProcessMessageAsync(MessageEvent messageEvent)
        {
            if (messageEvent.Message is IChannelRecipient r && r.RecipientChannel == ClientId)
                await Inbox.DeliverAsync(messageEvent).ConfigureAwait(false);
        }

        void IMessageHandler.OnError(Exception error) => Inbox.OnError(error);
    }
}
