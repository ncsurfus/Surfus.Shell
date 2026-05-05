using System;
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
        private byte[] _buffer = Array.Empty<byte>();
        private int _offset;
        private int _count;
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
        internal int Available { get { lock (_lock) { return _count; } } }

        /// <summary>
        /// Pushes data into the stream for consumers to read.
        /// The semaphore may accumulate counts if multiple pushes occur before ReadAsync wakes,
        /// causing spurious wakeups. This is harmless — ReadAsync checks _count > 0 under the lock first.
        /// </summary>
        // TODO: Every Push allocates a new byte[]. Consider using ArrayPool<byte> or a ring buffer
        // to reduce GC pressure for high-throughput scenarios.
        internal void Push(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0) return;

            lock (_lock)
            {
                var newBuffer = new byte[_count + data.Length];
                if (_count > 0)
                    Array.Copy(_buffer, _offset, newBuffer, 0, _count);
                data.CopyTo(newBuffer.AsSpan(_count));
                _buffer = newBuffer;
                _offset = 0;
                _count += data.Length;
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
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (offset + count > buffer.Length) throw new ArgumentException("Offset and count exceed buffer length.");

            while (true)
            {
                lock (_lock)
                {
                    if (_count > 0)
                    {
                        var bytesToRead = Math.Min(count, _count);
                        Array.Copy(_buffer, _offset, buffer, offset, bytesToRead);
                        _offset += bytesToRead;
                        _count -= bytesToRead;
                        OnConsumed?.Invoke(bytesToRead);
                        return bytesToRead;
                    }

                    if (_completed) return 0;
                }

                await _dataAvailable.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException("Use ReadAsync instead.");

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
