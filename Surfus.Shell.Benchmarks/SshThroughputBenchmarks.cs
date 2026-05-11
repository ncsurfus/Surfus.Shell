using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Surfus.Shell;

namespace Surfus.Shell.Benchmarks;

[MemoryDiagnoser]
[WarmupCount(1)]
[IterationCount(3)]
public class SshThroughputBenchmarks
{
    private Process _serverProcess = null!;
    private int _port;

    private const string User = "bench";
    private const string Pass = "bench";
    private const int DataSize = 100 * 1024 * 1024; // 100 MB

    [GlobalSetup]
    public void Setup()
    {
        var serverPath = FindServerBinary();
        var psi = new ProcessStartInfo(serverPath, "--timeout 300 --hostkey rsa --shell echo --user bench --pass bench")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        _serverProcess = Process.Start(psi) ?? throw new Exception("Failed to start test SSH server");

        for (var i = 0; i < 2; i++)
        {
            var line = _serverProcess.StandardOutput.ReadLine() ?? throw new Exception("Server exited");
            if (line.StartsWith("LISTENING:"))
                _port = int.Parse(line["LISTENING:".Length..]);
        }

        if (_port == 0)
            throw new Exception("Failed to read port from test SSH server");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        try { _serverProcess.Kill(entireProcessTree: true); } catch { }
        _serverProcess.Dispose();
    }

    [Benchmark]
    public async Task Download_100MB()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await using var client = new SshClient("127.0.0.1", (ushort)_port);
        await client.ConnectAsync(cts.Token);
        await client.AuthenticateAsync(User, Pass, cts.Token);

        var command = await client.CreateCommandAsync(cts.Token);
        await command.StartAsync($"head -c {DataSize} /dev/zero", cts.Token);

        long total = 0;
        var buf = new byte[64 * 1024];
        while (total < DataSize)
        {
            var n = await command.StandardOutput.ReadAsync(buf, cts.Token);
            if (n == 0) break;
            total += n;
        }
    }

    [Benchmark]
    public async Task Upload_100MB()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await using var client = new SshClient("127.0.0.1", (ushort)_port);
        await client.ConnectAsync(cts.Token);
        await client.AuthenticateAsync(User, Pass, cts.Token);

        var command = await client.CreateCommandAsync(cts.Token);
        // cat reads stdin and discards (output goes to channel stdout which we drain)
        await command.StartAsync("cat > /dev/null", cts.Token);

        var chunk = new byte[32 * 1024];
        long sent = 0;
        while (sent < DataSize)
        {
            var toSend = (int)Math.Min(chunk.Length, DataSize - sent);
            await command.StandardInput.WriteAsync(chunk.AsMemory(0, toSend), cts.Token);
            sent += toSend;
        }
        await command.StandardInput.DisposeAsync();

        // Drain stdout to let the channel close cleanly
        var drain = new byte[4096];
        while (await command.StandardOutput.ReadAsync(drain, cts.Token) > 0) { }
    }

    [Benchmark]
    public async Task ConnectAuthDisconnect()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var client = new SshClient("127.0.0.1", (ushort)_port);
        await client.ConnectAsync(cts.Token);
        await client.AuthenticateAsync(User, Pass, cts.Token);
    }

    private static string FindServerBinary()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10; i++)
        {
            var candidate = Path.Combine(dir, "Surfus.Shell.Tests", "testserver", "testserver");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                candidate += ".exe";
            if (File.Exists(candidate))
                return candidate;

            candidate = Path.Combine(dir, "testserver", "testserver");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                candidate += ".exe";
            if (File.Exists(candidate))
                return candidate;

            dir = Path.GetDirectoryName(dir)!;
        }
        throw new FileNotFoundException(
            "Could not find testserver binary. Run 'go build -o testserver .' in Surfus.Shell.Tests/testserver/"
        );
    }
}
