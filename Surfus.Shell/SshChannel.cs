using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Authentication;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;

namespace Surfus.Shell
{
    internal class SshChannel
    {
        private readonly SendMessageAsync _send;
        internal readonly SshMessageInbox Inbox = new();
        internal IDisposable Registration { get; set; }

        internal int WindowRefill { get; set; } = 50000;
        internal int SendWindow { get; set; }
        internal int ReceiveWindow { get; set; }
        internal uint ServerId { get; set; }
        internal uint ClientId { get; }
        internal bool IsOpen { get; private set; }

        /// <summary>
        /// Callback for received data.
        /// </summary>
        internal Action<byte[], int, int> OnDataReceived;

        /// <summary>
        /// Callback when EOF is received.
        /// </summary>
        internal Action<ChannelEof> OnChannelEofReceived;

        /// <summary>
        /// Callback when channel close is received.
        /// </summary>
        internal Action<ChannelClose> OnChannelCloseReceived;

        internal SshChannel(SendMessageAsync send, uint channelId)
        {
            _send = send;
            ClientId = channelId;
        }

        public void Dispose()
        {
            Registration?.Dispose();
            Inbox.Dispose();
        }

        internal async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            ReceiveWindow = (int)openMessage.InitialWindowSize;
            await _send(openMessage, cancellationToken).ConfigureAwait(false);

            var msg = await ReadChannelMessageAsync(cancellationToken).ConfigureAwait(false);
            switch (msg.Message)
            {
                case ChannelOpenConfirmation confirm:
                    ServerId = confirm.SenderChannel;
                    SendWindow = (int)confirm.InitialWindowSize;
                    IsOpen = true;
                    break;
                case ChannelOpenFailure:
                    throw new SshException("Server refused to open channel.");
                default:
                    throw new SshException($"Unexpected message during channel open: {msg.Type}");
            }
        }

        internal async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            await _send(requestMessage, cancellationToken).ConfigureAwait(false);

            var msg = await ReadChannelMessageAsync(cancellationToken).ConfigureAwait(false);
            switch (msg.Message)
            {
                case ChannelSuccess:
                    break;
                case ChannelFailure:
                    throw new SshException("Server had channel request failure.");
                default:
                    throw new SshException($"Unexpected message during channel request: {msg.Type}");
            }
        }

        internal async Task WriteDataAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            var totalBytesLeft = buffer.Length;
            var offset = 0;
            while (totalBytesLeft > 0)
            {
                // Wait for send window
                while (SendWindow == 0)
                {
                    await ProcessOneInboxMessageAsync(cancellationToken).ConfigureAwait(false);
                }

                var chunkSize = Math.Min(totalBytesLeft, SendWindow);
                var chunk = buffer;
                if (chunkSize < buffer.Length)
                {
                    chunk = new byte[chunkSize];
                    Array.Copy(buffer, offset, chunk, 0, chunkSize);
                }
                await _send(new ChannelData(ServerId, chunk), cancellationToken).ConfigureAwait(false);
                SendWindow -= chunkSize;
                totalBytesLeft -= chunkSize;
                offset += chunkSize;
            }
        }

        internal async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (IsOpen)
            {
                await _send(new ChannelClose(ServerId), cancellationToken).ConfigureAwait(false);
                IsOpen = false;
            }
        }

        /// <summary>
        /// Reads the next channel message, processing window adjusts and data inline.
        /// Control messages (open confirm/failure, success/failure, eof, close) are returned.
        /// </summary>
        private async Task<MessageEvent> ReadChannelMessageAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                var msg = await Inbox.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (await ProcessInlineMessage(msg).ConfigureAwait(false))
                    continue;
                return msg;
            }
        }

        /// <summary>
        /// Processes a single message from the inbox. Used by WriteDataAsync to
        /// drain messages while waiting for window adjusts.
        /// </summary>
        internal async Task ProcessOneInboxMessageAsync(CancellationToken cancellationToken)
        {
            var msg = await Inbox.ReadAsync(cancellationToken).ConfigureAwait(false);
            await ProcessInlineMessage(msg).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads messages from the inbox until EOF or close is received.
        /// Data messages are delivered via OnDataReceived callback.
        /// Window adjusts are handled inline.
        /// </summary>
        internal async Task DrainUntilClosedAsync(CancellationToken cancellationToken)
        {
            while (IsOpen)
            {
                var msg = await Inbox.ReadAsync(cancellationToken).ConfigureAwait(false);

                switch (msg.Message)
                {
                    case ChannelWindowAdjust adjust:
                        SendWindow += (int)adjust.BytesToAdd;
                        break;

                    case ChannelData data:
                        await HandleDataAsync(data, cancellationToken).ConfigureAwait(false);
                        break;

                    case ChannelEof eof:
                        OnChannelEofReceived?.Invoke(eof);
                        return;

                    case ChannelClose close:
                        IsOpen = false;
                        OnChannelCloseReceived?.Invoke(close);
                        return;

                    default:
                        break;
                }
            }
        }

        /// <summary>
        /// Handles messages that can arrive at any time (window adjust, data, eof, close).
        /// Returns true if the message was handled inline, false if it should be returned to the caller.
        /// </summary>
        private async Task<bool> ProcessInlineMessage(MessageEvent msg)
        {
            switch (msg.Message)
            {
                case ChannelWindowAdjust adjust:
                    SendWindow += (int)adjust.BytesToAdd;
                    return true;

                case ChannelData data:
                    await HandleDataAsync(data, CancellationToken.None).ConfigureAwait(false);
                    return true;

                case ChannelEof eof:
                    OnChannelEofReceived?.Invoke(eof);
                    return true;

                case ChannelClose close:
                    IsOpen = false;
                    OnChannelCloseReceived?.Invoke(close);
                    return true;

                default:
                    return false;
            }
        }

        private async Task HandleDataAsync(ChannelData message, CancellationToken cancellationToken)
        {
            if (ReceiveWindow <= 0) return;

            var length = Math.Min(message.Data.Length, ReceiveWindow);
            ReceiveWindow -= length;

            if (ReceiveWindow <= 0)
            {
                await _send(new ChannelWindowAdjust(ServerId, (uint)WindowRefill), cancellationToken).ConfigureAwait(false);
                ReceiveWindow += WindowRefill;
            }

            OnDataReceived?.Invoke(message.Data, 0, length);
        }


        internal void ProcessMessage(MessageEvent messageEvent) => Inbox.Deliver(messageEvent);

        internal void OnError(Exception error) => Inbox.OnError(error);
    }
}
