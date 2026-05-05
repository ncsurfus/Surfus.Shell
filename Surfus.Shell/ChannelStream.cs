using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    /// <summary>
    /// A readable stream backed by a producer/consumer buffer.
    /// The channel writes data via <see cref="Push"/>; consumers read via standard Stream methods.
    /// </summary>
    internal class ChannelStream : Stream
    {
        private readonly SemaphoreSlim _dataAvailable = new(0);
        private readonly object _lock = new();
        private readonly Queue<ReadOnlyMemory<byte>> _segments = new();
        private int _totalBytes;
        private int _segmentOffset;
        private bool _completed;
        private bool _disposed;

        /// <summary>
        /// Called when data is consumed by a reader, with the number of bytes consumed.
        /// Used by the channel to replenish the receive window.
        /// </summary>
        internal Action<int> OnConsumed;

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
        /// Returns the number of bytes currently buffered and available for reading without blocking.
        /// </summary>
        internal int Available
        {
            get
            {
                lock (_lock)
                {
                    return _totalBytes;
                }
            }
        }

        /// <summary>
        /// Pushes data into the stream for consumers to read.
        /// </summary>
        internal void Push(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
                return;

            lock (_lock)
            {
                var copy = new byte[data.Length];
                data.CopyTo(copy);
                _segments.Enqueue(copy);
                _totalBytes += data.Length;
            }

            _dataAvailable.Release();
        }

        /// <summary>
        /// Signals that no more data will be pushed.
        /// </summary>
        internal void Complete()
        {
            lock (_lock)
            {
                _completed = true;
            }
            _dataAvailable.Release();
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (offset + count > buffer.Length)
                throw new ArgumentException("Offset and count exceed buffer length.");

            while (true)
            {
                lock (_lock)
                {
                    if (_totalBytes > 0)
                    {
                        var bytesToRead = Math.Min(count, _totalBytes);
                        var totalCopied = 0;

                        while (totalCopied < bytesToRead)
                        {
                            var segment = _segments.Peek().Span;
                            var available = segment.Length - _segmentOffset;
                            var toCopy = Math.Min(available, bytesToRead - totalCopied);
                            segment.Slice(_segmentOffset, toCopy).CopyTo(buffer.AsSpan(offset + totalCopied));
                            totalCopied += toCopy;
                            _segmentOffset += toCopy;

                            if (_segmentOffset == segment.Length)
                            {
                                _segments.Dequeue();
                                _segmentOffset = 0;
                            }
                        }

                        _totalBytes -= bytesToRead;
                        OnConsumed?.Invoke(bytesToRead);
                        return bytesToRead;
                    }

                    if (_completed)
                        return 0;
                }

                await _dataAvailable.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

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
                _dataAvailable.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
