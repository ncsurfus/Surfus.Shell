using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    /// <summary>
    /// A writable stream that sends data to the remote process via the SSH channel.
    /// Use DisposeAsync to close the stream and send EOF to the remote side.
    /// </summary>
    internal class ChannelInputStream : Stream, IAsyncDisposable
    {
        private readonly SshChannel _channel;
        private bool _closed;

        internal ChannelInputStream(SshChannel channel)
        {
            _channel = channel;
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => !_closed;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException("Use WriteAsync instead.");

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (_closed) throw new ObjectDisposedException(nameof(ChannelInputStream));
            if (count == 0) return;

            await _channel.WriteDataAsync(new ReadOnlyMemory<byte>(buffer, offset, count), cancellationToken).ConfigureAwait(false);
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_closed) throw new ObjectDisposedException(nameof(ChannelInputStream));
            if (buffer.Length == 0) return;

            await _channel.WriteDataAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override async ValueTask DisposeAsync()
        {
            if (!_closed)
            {
                _closed = true;
                try
                {
                    await _channel.SendEofAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch { }
            }
            GC.SuppressFinalize(this);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_closed)
            {
                _closed = true;
                // Best-effort EOF — prefer DisposeAsync.
            }
            base.Dispose(disposing);
        }
    }
}
