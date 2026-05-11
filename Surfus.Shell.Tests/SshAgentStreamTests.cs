using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Tests;

public class SshAgentStreamTests
{
    [Fact]
    public async Task ListKeys_OverStream_ParsesResponse()
    {
        // Simulate an agent response: SSH_AGENT_IDENTITIES_ANSWER with 1 ed25519 key
        var keyTypeBytes = "ssh-ed25519"u8.ToArray();
        var keyData = new byte[32]; // fake public key bytes
        var commentBytes = "test@host"u8.ToArray();

        // Build key blob: string key_type + string key_data
        var keyBlob = BuildBlob(w =>
        {
            WriteString(w, keyTypeBytes);
            WriteString(w, keyData);
        });

        // Build agent response payload: byte type + uint32 count + (string blob + string comment)
        var response = BuildBlob(w =>
        {
            w.WriteByte(12); // SSH_AGENT_IDENTITIES_ANSWER
            WriteUInt32(w, 1);
            WriteString(w, keyBlob);
            WriteString(w, commentBytes);
        });

        // Frame it with length prefix
        var framed = new MemoryStream();
        WriteUInt32(framed, (uint)response.Length);
        framed.Write(response);
        framed.Position = 0;

        // Use a duplex stream: reads from framed response, writes to sink
        using var stream = new DuplexStream(framed, new MemoryStream());
        using var agent = new SshAgentClient(stream);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var keys = await agent.ListKeysAsync(cts.Token);

        Assert.Single(keys);
        Assert.Equal("ssh-ed25519", keys[0].KeyType);
        Assert.Equal("test@host", keys[0].Comment);
    }

    [Fact]
    public async Task ListKeys_AgentFailure_Throws()
    {
        // Agent returns SSH_AGENT_FAILURE
        var response = new byte[] { 5 }; // SSH_AGENT_FAILURE
        var framed = new MemoryStream();
        WriteUInt32(framed, (uint)response.Length);
        framed.Write(response);
        framed.Position = 0;

        using var stream = new DuplexStream(framed, new MemoryStream());
        using var agent = new SshAgentClient(stream);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<SshException>(() => agent.ListKeysAsync(cts.Token));
    }

    [Fact]
    public void Constructor_NullStream_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new SshAgentClient(null!));
    }

    private static byte[] BuildBlob(Action<MemoryStream> write)
    {
        var ms = new MemoryStream();
        write(ms);
        return ms.ToArray();
    }

    private static void WriteString(MemoryStream ms, ReadOnlySpan<byte> data)
    {
        WriteUInt32(ms, (uint)data.Length);
        ms.Write(data);
    }

    private static void WriteUInt32(Stream s, uint value)
    {
        s.WriteByte((byte)(value >> 24));
        s.WriteByte((byte)(value >> 16));
        s.WriteByte((byte)(value >> 8));
        s.WriteByte((byte)value);
    }

    /// <summary>
    /// A stream that reads from one stream and writes to another.
    /// </summary>
    private sealed class DuplexStream(Stream readStream, Stream writeStream) : Stream
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

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                readStream.Dispose();
                writeStream.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
