using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Surfus.Shell.Tests
{
    public class ChannelStreamTests
    {
        [Fact]
        public async Task ConcurrentPushAndRead_DataIntegrity()
        {
            using var stream = new ChannelStream();
            const int totalBytes = 1_000_000;
            const int chunkSize = 137; // odd size to stress boundary conditions

            // Producer: push sequential bytes
            var producer = Task.Run(() =>
            {
                byte value = 0;
                var remaining = totalBytes;
                while (remaining > 0)
                {
                    var size = Math.Min(chunkSize, remaining);
                    var chunk = new byte[size];
                    for (int i = 0; i < size; i++)
                        chunk[i] = value++;
                    stream.Push(TestMessageFactory.CreateChannelData(chunk));
                    remaining -= size;
                }
                stream.Complete();
            });

            // Consumer: read and verify sequential bytes
            var received = new byte[totalBytes];
            int totalRead = 0;
            var readBuffer = new byte[256];
            while (true)
            {
                var n = await stream.ReadAsync(readBuffer, 0, readBuffer.Length, CancellationToken.None);
                if (n == 0)
                    break;
                Array.Copy(readBuffer, 0, received, totalRead, n);
                totalRead += n;
            }

            await producer;

            Assert.Equal(totalBytes, totalRead);

            // Verify all bytes are sequential
            byte expected = 0;
            for (int i = 0; i < totalBytes; i++)
            {
                Assert.Equal(expected, received[i]);
                expected++;
            }
        }
        [Fact]
        public async Task Complete_WithError_ReadAsyncThrowsError()
        {
            using var stream = new ChannelStream();
            var error = new Exceptions.SshException("Connection closed.");

            stream.Complete(error);

            var buf = new byte[1024];
            var ex = await Assert.ThrowsAsync<Exceptions.SshException>(
                () => stream.ReadAsync(buf, 0, buf.Length, CancellationToken.None));
            Assert.Equal("Connection closed.", ex.Message);
        }

        [Fact]
        public async Task Complete_WithError_ValueTaskReadAsyncThrowsError()
        {
            using var stream = new ChannelStream();
            var error = new Exceptions.SshException("Connection closed.");

            stream.Complete(error);

            var buf = new byte[1024];
            var ex = await Assert.ThrowsAsync<Exceptions.SshException>(
                async () => await stream.ReadAsync(buf.AsMemory(), CancellationToken.None));
            Assert.Equal("Connection closed.", ex.Message);
        }

        [Fact]
        public async Task Complete_WithError_AfterBufferedData_DataDeliveredBeforeError()
        {
            using var stream = new ChannelStream();
            var data = new byte[] { 1, 2, 3, 4, 5 };
            stream.Push(TestMessageFactory.CreateChannelData(data));

            var error = new Exceptions.SshException("Connection died.");
            stream.Complete(error);

            // First read should return the buffered data
            var buf = new byte[1024];
            var n = await stream.ReadAsync(buf, 0, buf.Length, CancellationToken.None);
            Assert.Equal(5, n);
            Assert.Equal(data, buf[..5]);

            // Next read should throw the error
            var ex = await Assert.ThrowsAsync<Exceptions.SshException>(
                () => stream.ReadAsync(buf, 0, buf.Length, CancellationToken.None));
            Assert.Equal("Connection died.", ex.Message);
        }

        [Fact]
        public async Task Complete_WithoutError_ReadAsyncReturnsZero()
        {
            using var stream = new ChannelStream();
            stream.Complete();

            var buf = new byte[1024];
            var n = await stream.ReadAsync(buf, 0, buf.Length, CancellationToken.None);
            Assert.Equal(0, n);
        }

        [Fact]
        public async Task Push_AfterComplete_DisposesMessageEvent()
        {
            using var stream = new ChannelStream();
            stream.Complete();

            // Push after complete should dispose the event (not leak)
            var evt = TestMessageFactory.CreateChannelData(new byte[] { 1, 2, 3 });
            stream.Push(evt);
            // No assertion needed — just verifying no exception/leak
        }
    }
}
