using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Tests;

public class SshVersionExchangeTests
{
    private const string ClientVersion = "SSH-2.0-Surfus-1.00";

    [Fact]
    public async Task HappyPath_ReturnsServerVersion()
    {
        var stream = MakeStream("SSH-2.0-OpenSSH_9.0\r\n");

        var result = await SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None);

        Assert.Equal("SSH-2.0-OpenSSH_9.0", result.ServerVersion);
        Assert.Empty(result.BannerLines);
        AssertClientVersionSent(stream);
    }

    [Fact]
    public async Task HappyPath_Ssh199_Accepted()
    {
        var stream = MakeStream("SSH-1.99-Server\r\n");

        var result = await SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None);

        Assert.Equal("SSH-1.99-Server", result.ServerVersion);
    }

    [Fact]
    public async Task HappyPath_LineFeedOnly()
    {
        var stream = MakeStream("SSH-2.0-NoCarriageReturn\n");

        var result = await SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None);

        Assert.Equal("SSH-2.0-NoCarriageReturn", result.ServerVersion);
    }

    [Fact]
    public async Task BannerLines_SkippedAndReturned()
    {
        var stream = MakeStream("Welcome to server\r\nPlease wait...\r\nSSH-2.0-MyServer\r\n");

        var result = await SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None);

        Assert.Equal("SSH-2.0-MyServer", result.ServerVersion);
        Assert.Equal(2, result.BannerLines.Count);
        Assert.Equal("Welcome to server", result.BannerLines[0]);
        Assert.Equal("Please wait...", result.BannerLines[1]);
    }

    [Fact]
    public async Task UnsupportedVersion_Throws()
    {
        var stream = MakeStream("SSH-1.0-OldServer\r\n");

        var ex = await Assert.ThrowsAsync<SshException>(
            () => SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None));

        Assert.Contains("not supported", ex.Message);
    }

    [Fact]
    public async Task LineTooLong_Throws()
    {
        var longLine = new string('A', 256) + "\r\n";
        var stream = MakeStream(longLine);

        await Assert.ThrowsAsync<SshException>(
            () => SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None));
    }

    [Fact]
    public async Task ConnectionClosedBeforeVersion_Throws()
    {
        var stream = MakeStream(""); // empty = immediate EOF

        await Assert.ThrowsAsync<SshException>(
            () => SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None));
    }

    [Fact]
    public async Task ConnectionClosedMidLine_Throws()
    {
        var stream = MakeStream("SSH-2.0-Partial"); // no newline, then EOF

        await Assert.ThrowsAsync<SshException>(
            () => SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None));
    }

    [Fact]
    public async Task Cancellation_Throws()
    {
        // A stream that blocks forever
        var stream = new BlockingStream();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => SshVersionExchange.ExchangeAsync(stream, ClientVersion, cts.Token));
    }

    [Fact]
    public async Task ClientVersionSentBeforeReading()
    {
        // Use a stream that records write order relative to reads
        var ordered = new OrderTrackingStream("SSH-2.0-Server\r\n");

        await SshVersionExchange.ExchangeAsync(ordered, ClientVersion, CancellationToken.None);

        // Client version must be written before any read occurs
        Assert.True(ordered.FirstWriteBeforeFirstRead);
    }

    [Fact]
    public async Task VersionAtMaxLength_Accepted()
    {
        // 255 bytes total including CR LF: 253 content + \r\n
        var version = "SSH-2.0-" + new string('X', 245);
        var stream = MakeStream(version + "\r\n");

        var result = await SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None);

        Assert.Equal(version, result.ServerVersion);
    }

    [Fact]
    public async Task NonAsciiInVersion_Throws()
    {
        // Construct raw bytes with 0xFF in the version string
        var raw = Encoding.ASCII.GetBytes("SSH-2.0-Server_\r\n");
        raw[15] = 0xFF; // replace '_' with non-ASCII byte
        var stream = new DuplexMemoryStream(new MemoryStream(raw), new MemoryStream());

        await Assert.ThrowsAsync<SshException>(
            () => SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None));
    }

    [Fact]
    public async Task BannerLines_DecodedAsUtf8()
    {
        // "Willkommen" with a German ü (U+00FC = 0xC3 0xBC in UTF-8)
        var bannerBytes = Encoding.UTF8.GetBytes("Willk\u00fcmmen\r\n");
        var versionBytes = Encoding.ASCII.GetBytes("SSH-2.0-Server\r\n");
        var raw = new byte[bannerBytes.Length + versionBytes.Length];
        bannerBytes.CopyTo(raw, 0);
        versionBytes.CopyTo(raw, bannerBytes.Length);
        var stream = new DuplexMemoryStream(new MemoryStream(raw), new MemoryStream());

        var result = await SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None);

        Assert.Single(result.BannerLines);
        Assert.Equal("Willk\u00fcmmen", result.BannerLines[0]);
    }

    [Fact]
    public async Task TooManyBannerLines_Throws()
    {
        // RFC doesn't specify a limit but we should have a reasonable one to prevent abuse
        var sb = new StringBuilder();
        for (var i = 0; i < 1024; i++)
            sb.Append($"banner line {i}\r\n");
        sb.Append("SSH-2.0-Server\r\n");
        var stream = MakeStream(sb.ToString());

        await Assert.ThrowsAsync<SshException>(
            () => SshVersionExchange.ExchangeAsync(stream, ClientVersion, CancellationToken.None));
    }

    private static DuplexMemoryStream MakeStream(string serverData)
    {
        var readData = Encoding.ASCII.GetBytes(serverData);
        return new DuplexMemoryStream(new MemoryStream(readData), new MemoryStream());
    }

    private static void AssertClientVersionSent(DuplexMemoryStream stream)
    {
        var written = stream.GetWrittenBytes();
        var expected = Encoding.ASCII.GetBytes(ClientVersion + "\r\n");
        Assert.Equal(expected, written);
    }

    /// <summary>
    /// A stream backed by separate read/write MemoryStreams.
    /// </summary>
    internal sealed class DuplexMemoryStream(MemoryStream readStream, MemoryStream writeStream) : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => readStream.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => readStream.ReadAsync(buffer, ct);
        public override void Write(byte[] buffer, int offset, int count) => writeStream.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => writeStream.WriteAsync(buffer, ct);
        public override Task FlushAsync(CancellationToken ct) => writeStream.FlushAsync(ct);
        public override void Flush() => writeStream.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public byte[] GetWrittenBytes()
        {
            return writeStream.ToArray();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { readStream.Dispose(); writeStream.Dispose(); }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// A stream that never returns data, for testing cancellation.
    /// </summary>
    private sealed class BlockingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            await Task.Delay(Timeout.Infinite, ct);
            return 0;
        }

        public override void Write(byte[] buffer, int offset, int count) { }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => ValueTask.CompletedTask;
        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    /// <summary>
    /// Tracks whether the first write happened before the first read.
    /// </summary>
    internal sealed class OrderTrackingStream : Stream
    {
        private readonly MemoryStream _readStream;
        private readonly MemoryStream _writeStream = new();
        private bool _hasRead;
        private bool _hasWritten;

        public bool FirstWriteBeforeFirstRead { get; private set; }

        public OrderTrackingStream(string serverData)
        {
            _readStream = new MemoryStream(Encoding.ASCII.GetBytes(serverData));
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!_hasRead) { _hasRead = true; }
            return _readStream.Read(buffer, offset, count);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (!_hasRead) { _hasRead = true; }
            return _readStream.ReadAsync(buffer, ct);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!_hasWritten) { _hasWritten = true; FirstWriteBeforeFirstRead = !_hasRead; }
            _writeStream.Write(buffer, offset, count);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            if (!_hasWritten) { _hasWritten = true; FirstWriteBeforeFirstRead = !_hasRead; }
            return _writeStream.WriteAsync(buffer, ct);
        }

        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) { _readStream.Dispose(); _writeStream.Dispose(); }
            base.Dispose(disposing);
        }
    }
}
