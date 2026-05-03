using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;

namespace Surfus.Shell
{
    internal class SshChannel : IMessageHandler, IAsyncDisposable
    {
        internal readonly SshMessageInbox Inbox = new();
        internal IDisposable Registration { get; set; }

        internal int WindowRefill { get; set; } = 50000;
        internal int SendWindow { get; set; }
        internal int ReceiveWindow { get; set; }
        internal uint ServerId { get; set; }
        internal uint ClientId { get; }
        internal bool IsOpen { get; private set; }

        internal bool CombineStderr { get; set; }

        internal readonly ChannelStream Stdout = new();
        internal readonly ChannelStream Stderr = new();
        internal ChannelInputStream Stdin { get; private set; }

        private int _consumedBytes;
        private readonly CancellationTokenSource _pumpCts = new();
        private Task _pumpTask;

        /// <summary>
        /// Set by RequestAsync, completed by the pump when ChannelSuccess/ChannelFailure arrives.
        /// </summary>
        private TaskCompletionSource<bool> _pendingRequest;

        /// <summary>
        /// Signaled by the pump when SendWindow becomes non-zero.
        /// </summary>
        private TaskCompletionSource _sendWindowAvailable = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal SshChannel(uint channelId)
        {
            ClientId = channelId;
            Stdin = new ChannelInputStream(this);
            Stdout.OnConsumed = OnBytesConsumed;
            Stderr.OnConsumed = OnBytesConsumed;
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

        internal async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            ReceiveWindow = (int)openMessage.InitialWindowSize;
            await Inbox.SendAsync(openMessage, cancellationToken).ConfigureAwait(false);

            // Read directly before pump starts.
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

        internal async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            _pendingRequest = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            await Inbox.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);

            using var reg = cancellationToken.Register(() => _pendingRequest.TrySetCanceled(cancellationToken));
            var success = await _pendingRequest.Task.ConfigureAwait(false);
            _pendingRequest = null;

            if (!success)
                throw new SshException("Server had channel request failure.");
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

        internal async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (IsOpen)
            {
                await Inbox.SendAsync(new ChannelClose(ServerId), cancellationToken).ConfigureAwait(false);
                IsOpen = false;
            }
        }

        internal async Task SendMessageAsync(IClientMessage message, CancellationToken cancellationToken)
        {
            await Inbox.SendAsync(message, cancellationToken).ConfigureAwait(false);
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

        public Func<IClientMessage, CancellationToken, Task> OnSend { set => Inbox.OnSend = value; }

        public async ValueTask ProcessMessageAsync(MessageEvent messageEvent)
        {
            if (messageEvent.Message is IChannelRecipient r && r.RecipientChannel == ClientId)
                await Inbox.DeliverAsync(messageEvent).ConfigureAwait(false);
        }

        public void OnError(Exception error) => Inbox.OnError(error);
    }
}
