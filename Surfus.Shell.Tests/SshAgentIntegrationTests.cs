using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Surfus.Shell.Tests;

public class SshAgentIntegrationTests : IAsyncLifetime
{
    private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    private string _tempDir = null!;
    private string _keyPath = null!;
    private string _pubKeyPath = null!;
    private string _agentSocket = null!;
    private int _agentPid;

    private static CancellationToken Timeout(int seconds = 10) => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    public async Task InitializeAsync()
    {
        if (IsWindows)
            return;

        _tempDir = Path.Combine(Path.GetTempPath(), $"ss-{Guid.NewGuid().ToString("N")[..8]}");
        Directory.CreateDirectory(_tempDir);

        _keyPath = Path.Combine(_tempDir, "testkey");
        _pubKeyPath = _keyPath + ".pub";
        _agentSocket = Path.Combine(_tempDir, "agent.sock");

        await RunAsync("ssh-keygen", $"-t ed25519 -f {_keyPath} -N \"\" -q");

        var agentOutput = await RunAsync("ssh-agent", $"-a {_agentSocket}");
        foreach (var line in agentOutput.Split('\n'))
        {
            if (line.StartsWith("SSH_AGENT_PID="))
                _agentPid = int.Parse(line.Split('=', ';')[1]);
        }

        await RunAsync("ssh-add", _keyPath, ("SSH_AUTH_SOCK", _agentSocket));
    }

    public Task DisposeAsync()
    {
        if (IsWindows)
            return Task.CompletedTask;

        if (_agentPid > 0)
        {
            try
            {
                Process.GetProcessById(_agentPid).Kill();
            }
            catch { }
        }
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch { }
        return Task.CompletedTask;
    }

    [Fact]
    public async Task AgentAuth_ListKeys()
    {
        if (IsWindows)
            return;

        using var agent = await SshAgentClient.ConnectAsync(_agentSocket, Timeout());
        var keys = await agent.ListKeysAsync(Timeout());
        Assert.Single(keys);
        Assert.Equal("ssh-ed25519", keys[0].KeyType);
    }

    [Fact]
    public async Task AgentAuth_ConnectAndAuthenticate()
    {
        if (IsWindows)
            return;

        await using var server = await SshTestServer.StartAsync(authorizedKeyPath: _pubKeyPath);
        using var agent = await SshAgentClient.ConnectAsync(_agentSocket, Timeout());
        var keys = await agent.ListKeysAsync(Timeout());

        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync("testuser", agent, keys[0], Timeout());

        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task AgentAuth_TryAllKeys()
    {
        if (IsWindows)
            return;

        await using var server = await SshTestServer.StartAsync(authorizedKeyPath: _pubKeyPath);
        using var agent = await SshAgentClient.ConnectAsync(_agentSocket, Timeout());

        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync("testuser", agent, Timeout());

        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task AgentAuth_ExecAfterAuth()
    {
        if (IsWindows)
            return;

        await using var server = await SshTestServer.StartAsync(authorizedKeyPath: _pubKeyPath);
        using var agent = await SshAgentClient.ConnectAsync(_agentSocket, Timeout());
        var keys = await agent.ListKeysAsync(Timeout());

        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync("testuser", agent, keys[0], Timeout());

        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo agent-works", Timeout());
        var ms = new MemoryStream();
        await command.StandardOutput.CopyToAsync(ms, Timeout());
        var result = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        Assert.Contains("agent-works", result);
    }

    private static async Task<string> RunAsync(string command, string args, params (string key, string value)[] env)
    {
        var psi = new ProcessStartInfo(command, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var (key, value) in env)
            psi.Environment[key] = value;

        var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        await proc.WaitForExitAsync();
        if (proc.ExitCode != 0)
        {
            var stderr = await proc.StandardError.ReadToEndAsync();
            throw new Exception($"{command} {args} failed (exit {proc.ExitCode}): {stderr}");
        }
        return stdout;
    }
}
