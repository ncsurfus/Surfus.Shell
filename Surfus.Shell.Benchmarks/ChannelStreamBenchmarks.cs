using System;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Surfus.Shell;

namespace Surfus.Shell.Benchmarks;

[MemoryDiagnoser]
public class ChannelStreamBenchmarks
{
    private byte[] _1KB = null!;
    private byte[] _32KB = null!;
    private byte[] _100Bytes = null!;

    [GlobalSetup]
    public void Setup()
    {
        _1KB = new byte[1024];
        _32KB = new byte[32 * 1024];
        _100Bytes = new byte[100];
        Random.Shared.NextBytes(_1KB);
        Random.Shared.NextBytes(_32KB);
        Random.Shared.NextBytes(_100Bytes);
    }

    [Benchmark]
    public void Push_SmallPacket()
    {
        using var stream = new ChannelStream();
        stream.Push(_1KB);
    }

    [Benchmark]
    public void Push_LargePacket()
    {
        using var stream = new ChannelStream();
        stream.Push(_32KB);
    }

    [Benchmark]
    public async Task PushAndRead_SmallPacket()
    {
        using var stream = new ChannelStream();
        stream.Push(_1KB);
        var buf = new byte[1024];
        await stream.ReadAsync(buf, 0, buf.Length, CancellationToken.None);
    }

    [Benchmark]
    public async Task PushAndRead_LargePacket()
    {
        using var stream = new ChannelStream();
        stream.Push(_32KB);
        var buf = new byte[32 * 1024];
        await stream.ReadAsync(buf, 0, buf.Length, CancellationToken.None);
    }

    [Benchmark]
    public void Push_ManySmallPackets()
    {
        using var stream = new ChannelStream();
        for (int i = 0; i < 100; i++)
            stream.Push(_100Bytes);
    }

    [Benchmark]
    public async Task ConcurrentPushAndRead()
    {
        using var stream = new ChannelStream();
        var totalBytes = 1024 * 1024;
        var chunkSize = 1024;

        var producer = Task.Run(() =>
        {
            var chunk = _1KB;
            for (int i = 0; i < totalBytes / chunkSize; i++)
                stream.Push(chunk);
            stream.Complete();
        });

        var consumer = Task.Run(async () =>
        {
            var buf = new byte[chunkSize];
            int total = 0;
            while (total < totalBytes)
            {
                var read = await stream.ReadAsync(buf, 0, buf.Length, CancellationToken.None);
                if (read == 0)
                    break;
                total += read;
            }
        });

        await Task.WhenAll(producer, consumer);
    }
}
