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
        private byte[] _buffer = Array.Empty<byte>();
        private int _offset;
        private int _count;
        private bool _completed;

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
        internal int Available => _count;

        /// <summary>
        /// Pushes data into the stream for consumers to read.
        /// </summary>
        internal void Push(byte[] data, int offset, int count)
        {
            if (count == 0) return;

            // Append to existing buffer
            var newBuffer = new byte[_count + count];
            if (_count > 0)
                Array.Copy(_buffer, _offset, newBuffer, 0, _count);
            Array.Copy(data, offset, newBuffer, _count, count);
            _buffer = newBuffer;
            _offset = 0;
            _count += count;

            _dataAvailable.Release();
        }

        /// <summary>
        /// Signals that no more data will be pushed.
        /// </summary>
        internal void Complete()
        {
            _completed = true;
            _dataAvailable.Release();
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (_count == 0)
            {
                if (_completed) return 0;
                await _dataAvailable.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            var bytesToRead = Math.Min(count, _count);
            Array.Copy(_buffer, _offset, buffer, offset, bytesToRead);
            _offset += bytesToRead;
            _count -= bytesToRead;
            OnConsumed?.Invoke(bytesToRead);
            return bytesToRead;
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException("Use ReadAsync instead.");

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Complete();
                _dataAvailable.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
