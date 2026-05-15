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
    }
}
