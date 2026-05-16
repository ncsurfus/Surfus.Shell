using System.Diagnostics;

namespace Surfus.Shell.Tests;

/// <summary>
/// Launches an OpenSSH sshd in user mode for integration testing.
/// Works on macOS (Homebrew) and Linux.
/// </summary>
public sealed class OpenSshTestServer : IAsyncDisposable
{
    private readonly Process _process;
    private readonly string _tempDir;

    public int Port { get; }
    public string User { get; } = "testuser";
    public string Password { get; } = "testpass";
    public string PrivateKeyPath { get; }

    private OpenSshTestServer(Process process, string tempDir, int port, string privateKeyPath)
    {
        _process = process;
        _tempDir = tempDir;
        Port = port;
        PrivateKeyPath = privateKeyPath;
    }

    public static async Task<OpenSshTestServer> StartAsync(
        string? kexAlgorithms = null,
        string? ciphers = null,
        string? macs = null,
        string? rekeyLimit = null)
    {
        var sshdPath = FindSshd();
        if (sshdPath == null)
            throw new InvalidOperationException("sshd not found. Install via 'brew install openssh' (macOS) or ensure /usr/sbin/sshd exists (Linux). Skip these tests with --filter \"!OpenSsh\".");
        var tempDir = Path.Combine(Path.GetTempPath(), $"surfus-sshd-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        // Generate host key (ECDSA — supported by our library)
        var hostKeyPath = Path.Combine(tempDir, "host_key");
        await RunAsync("ssh-keygen", $"-t ecdsa -b 256 -f {hostKeyPath} -N \"\"");

        // Generate user key pair (ECDSA — supported by our library, PEM format)
        var userKeyPath = Path.Combine(tempDir, "user_key");
        await RunAsync("ssh-keygen", $"-t ecdsa -b 256 -f {userKeyPath} -N \"\" -m PEM");

        // Create authorized_keys
        var pubKey = await File.ReadAllTextAsync($"{userKeyPath}.pub");
        var authKeysPath = Path.Combine(tempDir, "authorized_keys");
        await File.WriteAllTextAsync(authKeysPath, pubKey);

        // Write sshd_config
        var configPath = Path.Combine(tempDir, "sshd_config");
        var pidFile = Path.Combine(tempDir, "sshd.pid");
        var port = new Random().Next(10000, 60000);
        await File.WriteAllTextAsync(configPath, $"""
            Port {port}
            ListenAddress 127.0.0.1
            HostKey {hostKeyPath}
            AuthorizedKeysFile {authKeysPath}
            PasswordAuthentication no
            PubkeyAuthentication yes
            StrictModes no
            PidFile {pidFile}
            LogLevel DEBUG
            {(kexAlgorithms != null ? $"KexAlgorithms {kexAlgorithms}" : "")}
            {(ciphers != null ? $"Ciphers {ciphers}" : "")}
            {(macs != null ? $"MACs {macs}" : "")}
            {(rekeyLimit != null ? $"RekeyLimit {rekeyLimit}" : "")}
            """);

        // Start sshd in debug/foreground mode
        var psi = new ProcessStartInfo(sshdPath, $"-D -e -f {configPath}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        var process = Process.Start(psi) ?? throw new Exception("Failed to start sshd");

        // Wait for sshd to start listening
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            var line = await process.StandardError.ReadLineAsync() ?? "";
            if (line.Contains("Server listening"))
                break;
            if (process.HasExited)
            {
                var stderr = await process.StandardError.ReadToEndAsync();
                throw new Exception($"sshd exited immediately: {line}{stderr}");
            }
        }

        return new OpenSshTestServer(process, tempDir, port, userKeyPath);
    }

    public async ValueTask DisposeAsync()
    {
        try { if (!_process.HasExited) _process.Kill(entireProcessTree: true); } catch { }
        try { await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
        _process.Dispose();
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private static string? FindSshd()
    {
        // macOS Homebrew
        var brewPath = "/opt/homebrew/opt/openssh/sbin/sshd";
        if (File.Exists(brewPath)) return brewPath;

        // Intel Mac Homebrew
        var brewIntelPath = "/usr/local/opt/openssh/sbin/sshd";
        if (File.Exists(brewIntelPath)) return brewIntelPath;

        // Linux — system sshd
        var linuxPath = "/usr/sbin/sshd";
        if (File.Exists(linuxPath)) return linuxPath;

        return null;
    }

    private static async Task RunAsync(string command, string args)
    {
        var psi = new ProcessStartInfo(command, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        var proc = Process.Start(psi) ?? throw new Exception($"Failed to run {command}");
        await proc.WaitForExitAsync();
        if (proc.ExitCode != 0)
        {
            var err = await proc.StandardError.ReadToEndAsync();
            throw new Exception($"{command} failed: {err}");
        }
    }
}
