using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Surfus.Shell.Tests;

/// <summary>
/// Launches and manages the Go test SSH server process.
/// </summary>
public sealed class SshTestServer : IAsyncDisposable
{
    private readonly Process _process;

    public int Port { get; }
    public string HostKeyFingerprint { get; }

    private SshTestServer(Process process, int port, string fingerprint)
    {
        _process = process;
        Port = port;
        HostKeyFingerprint = fingerprint;
    }

    public static async Task<SshTestServer> StartAsync(
        string hostKey = "rsa",
        string shellMode = "echo",
        string? kex = null,
        string? ciphers = null,
        string? macs = null,
        string user = "testuser",
        string pass = "testpass",
        string? authorizedKeyPath = null)
    {
        var serverPath = FindServerBinary();

        var args = $"--timeout 30 --hostkey {hostKey} --shell {shellMode} --user {user} --pass {pass}";
        if (kex != null) args += $" --kex {kex}";
        if (ciphers != null) args += $" --ciphers {ciphers}";
        if (macs != null) args += $" --macs {macs}";
        if (authorizedKeyPath != null) args += $" --authorized-key {authorizedKeyPath}";

        var psi = new ProcessStartInfo(serverPath, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        var process = Process.Start(psi) ?? throw new Exception("Failed to start test SSH server");

        int port = 0;
        string fingerprint = "";

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        for (var i = 0; i < 2; i++)
        {
            var line = await process.StandardOutput.ReadLineAsync(cts.Token)
                ?? throw new Exception("Test SSH server exited unexpectedly");

            if (line.StartsWith("LISTENING:"))
                port = int.Parse(line["LISTENING:".Length..]);
            else if (line.StartsWith("HOSTKEY:"))
                fingerprint = line["HOSTKEY:".Length..];
        }

        if (port == 0)
            throw new Exception("Failed to read port from test SSH server");

        return new SshTestServer(process, port, fingerprint);
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch { }

        try
        {
            await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch { }

        _process.Dispose();
    }

    private static string FindServerBinary()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8; i++)
        {
            var candidate = Path.Combine(dir, "testserver", "testserver");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                candidate += ".exe";
            if (File.Exists(candidate))
                return candidate;
            dir = Path.GetDirectoryName(dir)!;
        }
        throw new FileNotFoundException(
            "Could not find testserver binary. Run 'go build -o testserver .' in Surfus.Shell.Tests/testserver/");
    }
}
