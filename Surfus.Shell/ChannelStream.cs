using System;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.MessageViews.Channel;

namespace Surfus.Shell
{
    /// <summary>
    /// A readable stream that delivers channel data bytes to consumers.
    /// Internally fed MessageEvents which it parses via ref struct views and disposes after consumption.
    /// </summary>
    internal sealed class ChannelStream : Stream
    {
        internal int MaxBufferSize { get; init; } = 16 * 1024 * 1024;

        private readonly Channel<MessageEvent> _channel = Channel.CreateUnbounded<MessageEvent>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true }
        );

        private MessageEvent? _currentEvent;
        private int _currentOffset;
        private long _bufferedBytes;

        internal Func<int, ValueTask>? OnConsumed { get; init; }

        internal ChannelStream() { }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        /// <summary>
        /// Pushes a MessageEvent containing channel data. The stream takes ownership and
        /// will dispose the event after the data is fully consumed.
        /// </summary>
        internal void Push(MessageEvent messageEvent)
        {
            var dataLength = GetDataLength(messageEvent);
            if (dataLength == 0)
            {
                messageEvent.Dispose();
                return;
            }

            if (Interlocked.Add(ref _bufferedBytes, dataLength) > MaxBufferSize)
            {
                Interlocked.Add(ref _bufferedBytes, -dataLength);
                messageEvent.Dispose();
                throw new SshException("Channel received too much data.");
            }

            if (!_channel.Writer.TryWrite(messageEvent))
            {
                Interlocked.Add(ref _bufferedBytes, -dataLength);
                messageEvent.Dispose();
            }
        }

        internal void Complete(Exception? error = null)
        {
            _error = error;
            _channel.Writer.TryComplete(error);
        }

        private volatile Exception? _error;

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            if (offset + count > buffer.Length)
                throw new ArgumentException("Offset and count exceed buffer length.");
            if (count == 0) return 0;

            var totalCopied = CopyFromCurrent(buffer.AsSpan(offset, count));

            if (totalCopied == 0)
            {
                if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (_error is { } err) throw err;
                    return 0;
                }
                if (!_channel.Reader.TryRead(out var evt))
                {
                    if (_error is { } err) throw err;
                    return 0;
                }

                ReleaseCurrent();
                _currentEvent = evt;
                _currentOffset = 0;
                totalCopied = CopyFromCurrent(buffer.AsSpan(offset, count));
            }

            if (totalCopied > 0)
            {
                Interlocked.Add(ref _bufferedBytes, -totalCopied);
                var handler = OnConsumed;
                if (handler != null)
                    await handler(totalCopied).ConfigureAwait(false);
            }

            return totalCopied;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0) return 0;

            var totalCopied = CopyFromCurrent(buffer.Span);

            if (totalCopied == 0)
            {
                if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (_error is { } err) throw err;
                    return 0;
                }
                if (!_channel.Reader.TryRead(out var evt))
                {
                    if (_error is { } err) throw err;
                    return 0;
                }

                ReleaseCurrent();
                _currentEvent = evt;
                _currentOffset = 0;
                totalCopied = CopyFromCurrent(buffer.Span);
            }

            if (totalCopied > 0)
            {
                Interlocked.Add(ref _bufferedBytes, -totalCopied);
                var handler = OnConsumed;
                if (handler != null)
                    await handler(totalCopied).ConfigureAwait(false);
            }

            return totalCopied;
        }

        private int CopyFromCurrent(Span<byte> dest)
        {
            if (_currentEvent == null || dest.Length == 0) return 0;

            var data = GetDataSpan(_currentEvent);
            var remaining = data.Slice(_currentOffset);
            var toCopy = Math.Min(remaining.Length, dest.Length);
            remaining.Slice(0, toCopy).CopyTo(dest);
            _currentOffset += toCopy;

            if (_currentOffset >= data.Length)
                ReleaseCurrent();

            return toCopy;
        }

        private static ReadOnlySpan<byte> GetDataSpan(MessageEvent evt)
        {
            var payload = evt.Payload;
            if (evt.Type == MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA)
            {
                var view = new ChannelExtendedDataView(payload);
                return view.Data;
            }
            else
            {
                var view = new ChannelDataView(payload);
                return view.Data;
            }
        }

        private static int GetDataLength(MessageEvent evt)
        {
            var payload = evt.Payload;
            if (evt.Type == MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA)
                return new ChannelExtendedDataView(payload).Data.Length;
            else
                return new ChannelDataView(payload).Data.Length;
        }

        private void ReleaseCurrent()
        {
            if (_currentEvent != null)
            {
                _currentEvent.Dispose();
                _currentEvent = null;
                _currentOffset = 0;
            }
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("Use ReadAsync instead.");
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                ReleaseCurrent();
                while (_channel.Reader.TryRead(out var evt))
                    evt.Dispose();
                Complete();
            }
            base.Dispose(disposing);
        }
    }
}
