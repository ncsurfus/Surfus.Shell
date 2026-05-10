using System;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell
{
    /// <summary>
    /// A readable stream backed by a Channel&lt;byte[]&gt;.
    /// The channel pushes data via <see cref="Push"/>; consumers read via standard Stream methods.
    /// Thread-safe: single producer (read loop), single consumer (user code).
    /// </summary>
    internal sealed class ChannelStream : Stream
    {
        /// <summary>
        /// Maximum bytes that may be buffered before the connection is terminated.
        /// Matches OpenSSH's CHAN_RBUF (16MB).
        /// </summary>
        internal int MaxBufferSize { get; init; } = 16 * 1024 * 1024;

        private readonly Channel<byte[]> _channel = Channel.CreateUnbounded<byte[]>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true }
        );

        private ReadOnlyMemory<byte> _current;
        private bool _disposed;
        private long _bufferedBytes;

        /// <summary>
        /// Called after data is consumed by a reader, with the number of bytes consumed.
        /// Used by the channel to replenish the SSH receive window. May be null.
        /// </summary>
        internal Func<int, ValueTask>? OnConsumed { get; init; }

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
        /// Pushes data into the stream for consumers to read.
        /// Called from the read loop (single producer).
        /// </summary>
        internal void Push(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return;
            }

            if (Interlocked.Add(ref _bufferedBytes, data.Length) > MaxBufferSize)
            {
                throw new SshException("Channel received too much data.");
            }

            _channel.Writer.TryWrite(data.ToArray());
        }

        /// <summary>
        /// Signals that no more data will be pushed.
        /// </summary>
        internal void Complete()
        {
            _channel.Writer.TryComplete();
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegative(count);

            if (offset + count > buffer.Length)
            {
                throw new ArgumentException("Offset and count exceed buffer length.");
            }

            if (count == 0)
            {
                return 0;
            }

            var totalCopied = CopyFromCurrent(buffer.AsSpan(offset, count));

            if (totalCopied == 0)
            {
                if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return 0;
                }

                if (!_channel.Reader.TryRead(out var segment))
                {
                    return 0; // Channel completed between WaitToRead and TryRead.
                }

                _current = segment;
                totalCopied = CopyFromCurrent(buffer.AsSpan(offset, count));
            }

            if (totalCopied > 0)
            {
                Interlocked.Add(ref _bufferedBytes, -totalCopied);
                var handler = OnConsumed;
                if (handler != null)
                {
                    await handler(totalCopied).ConfigureAwait(false);
                }
            }

            return totalCopied;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0)
            {
                return 0;
            }

            var totalCopied = CopyFromCurrent(buffer.Span);

            if (totalCopied == 0)
            {
                if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return 0;
                }

                if (!_channel.Reader.TryRead(out var segment))
                {
                    return 0; // Channel completed between WaitToRead and TryRead.
                }

                _current = segment;
                totalCopied = CopyFromCurrent(buffer.Span);
            }

            if (totalCopied > 0)
            {
                Interlocked.Add(ref _bufferedBytes, -totalCopied);
                var handler = OnConsumed;
                if (handler != null)
                {
                    await handler(totalCopied).ConfigureAwait(false);
                }
            }

            return totalCopied;
        }

        /// <summary>Copies bytes from the current buffered segment into <paramref name="dest"/> and advances the segment position.</summary>
        private int CopyFromCurrent(Span<byte> dest)
        {
            if (_current.Length == 0 || dest.Length == 0)
            {
                return 0;
            }

            var toCopy = Math.Min(_current.Length, dest.Length);
            _current.Span.Slice(0, toCopy).CopyTo(dest);
            _current = _current.Slice(toCopy);
            return toCopy;
        }

        /// <inheritdoc/>
        /// <remarks>Synchronous reads are not supported. Use ReadAsync.</remarks>
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("Use ReadAsync instead.");
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                _disposed = true;
                Complete();
            }
            base.Dispose(disposing);
        }
    }
}
