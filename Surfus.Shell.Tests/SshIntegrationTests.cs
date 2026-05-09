using System.IO;
using System.Linq;
using System.Text;

namespace Surfus.Shell.Tests;

[Collection("Integration")]
public class SshIntegrationTests
{
    private const string User = "testuser";
    private const string Pass = "testpass";

    private static CancellationToken Timeout(int seconds = 10) => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static async Task<string> ReadAllAsync(Stream stream, CancellationToken ct)
    {
        var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    // --- Auth ---

    [Fact]
    public async Task ConnectAndAuthenticate_Password()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task ConnectAndAuthenticate_KeyboardInteractive()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, (prompt, ct) => Task.FromResult(Pass), Timeout());
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task InvalidPassword_Throws()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await Assert.ThrowsAsync<Exceptions.SshInvalidCredentials>(() => client.AuthenticateAsync(User, "wrong", Timeout()));
    }

    [Fact]
    public async Task AuthRetry_WrongThenRight()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());

        await Assert.ThrowsAsync<Exceptions.SshInvalidCredentials>(() => client.AuthenticateAsync(User, "wrong", Timeout()));

        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
    }

    // --- Channels ---

    [Fact]
    public async Task ExecChannel_ReturnsOutput()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo hello", Timeout());
        var stdout = await ReadAllAsync(command.StandardOutput, Timeout());
        Assert.Contains("hello", stdout);
    }

    [Fact]
    public async Task ExecChannel_StderrSeparate()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo out && echo err >&2", Timeout());
        var stdout = await ReadAllAsync(command.StandardOutput, Timeout());
        var stderr = await ReadAllAsync(command.StandardError, Timeout());
        Assert.Contains("out", stdout);
        Assert.Contains("err", stderr);
        Assert.DoesNotContain("err", stdout);
    }

    [Fact]
    public async Task ExecChannel_StderrCombined()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var command = await client.CreateCommandAsync(Timeout(), combineStderr: true);
        await command.StartAsync("echo out && echo err >&2", Timeout());
        var stdout = await ReadAllAsync(command.StandardOutput, Timeout());
        var stderr = await ReadAllAsync(command.StandardError, Timeout());
        Assert.Contains("out", stdout);
        Assert.Contains("err", stdout);
        Assert.Empty(stderr);
    }

    [Fact]
    public async Task ExecChannel_StderrOnly()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo err >&2", Timeout());
        var stdout = await ReadAllAsync(command.StandardOutput, Timeout());
        var stderr = await ReadAllAsync(command.StandardError, Timeout());
        Assert.Contains("err", stderr);
        Assert.Empty(stdout);
    }

    [Fact]
    public async Task ShellChannel_CanWriteAndRead()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var terminal = await client.CreateTerminalAsync(Timeout());
        // Read some initial output from the shell
        var buf = new byte[4096];
        var n = await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, Timeout());
        Assert.True(n > 0);
    }

    [Fact]
    public async Task ShellChannel_WindowChange()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var terminal = await client.CreateTerminalAsync(Timeout());
        // Read initial prompt
        var buf = new byte[4096];
        await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, Timeout());
        // Send window-change and verify the terminal still works
        await terminal.SendWindowChangeAsync(120, 40, Timeout());
        var data = Encoding.UTF8.GetBytes("hello\n");
        await terminal.StandardInput.WriteAsync(data, 0, data.Length, Timeout());
        await terminal.StandardInput.FlushAsync(Timeout());
        var n = await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, Timeout());
        var output = Encoding.UTF8.GetString(buf, 0, n);
        Assert.Contains("hello", output);
    }

    // --- Host key ---

    [Fact]
    public async Task HostKeyCallback_ReceivesKey()
    {
        await using var server = await SshTestServer.StartAsync();
        byte[]? receivedKey = null;
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port)
        {
            HostKeyCallback = (key, ct) =>
            {
                receivedKey = key.ToArray();
                return Task.FromResult(true);
            },
        };
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.NotNull(receivedKey);
        Assert.True(receivedKey!.Length > 0);
    }

    [Fact]
    public async Task HostKeyCallback_RejectDisconnects()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port) { HostKeyCallback = (_, ct) => Task.FromResult(false) };
        await Assert.ThrowsAsync<Exceptions.SshException>(() => client.ConnectAsync(Timeout()));
    }

    [Theory]
    [InlineData("rsa")]
    [InlineData("ecdsa256")]
    [InlineData("ecdsa384")]
    [InlineData("ecdsa521")]
    public async Task HostKeyType(string hostKeyType)
    {
        await using var server = await SshTestServer.StartAsync(hostKey: hostKeyType);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
    }

    // --- Key exchange algorithms ---

    [Theory]
    [InlineData("diffie-hellman-group14-sha256")]
    [InlineData("diffie-hellman-group14-sha1")]
    [InlineData("diffie-hellman-group16-sha512")]
    [InlineData("diffie-hellman-group1-sha1")]
    [InlineData("diffie-hellman-group-exchange-sha256")]
    [InlineData("diffie-hellman-group-exchange-sha1")]
    [InlineData("ecdh-sha2-nistp256")]
    [InlineData("ecdh-sha2-nistp384")]
    [InlineData("ecdh-sha2-nistp521")]
    public async Task KexAlgorithm(string kex)
    {
        await using var server = await SshTestServer.StartAsync(kex: kex);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port)
        {
            Algorithms = new SshAlgorithms
            {
                KeyExchange = SshAlgorithms
                    .DefaultKeyExchange.Append(
                        new KeyExchangeDescriptor(
                            "diffie-hellman-group1-sha1",
                            (ctx, k) => new KeyExchange.DiffieHellman.DiffieHellmanGroup1Sha1(ctx, k)
                        )
                    )
                    .ToArray(),
            },
        };
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
    }

    // --- Ciphers ---

    [Theory]
    [InlineData("aes128-ctr")]
    [InlineData("aes192-ctr")]
    [InlineData("aes256-ctr")]
    [InlineData("aes128-cbc")]
    [InlineData("3des-cbc")]
    public async Task Cipher(string cipher)
    {
        // Go's x/crypto/ssh has a bug with ETM+CBC, so force non-ETM MAC for CBC ciphers.
        var mac = cipher.Contains("cbc") ? "hmac-sha2-256" : null;
        await using var server = await SshTestServer.StartAsync(ciphers: cipher, macs: mac);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
    }

    // --- MACs ---

    [Theory]
    [InlineData("hmac-sha2-256")]
    [InlineData("hmac-sha2-512")]
    [InlineData("hmac-sha2-256-etm@openssh.com")]
    [InlineData("hmac-sha2-512-etm@openssh.com")]
    [InlineData("hmac-sha1")]
    [InlineData("hmac-sha1-96")]
    public async Task Mac(string mac)
    {
        await using var server = await SshTestServer.StartAsync(macs: mac);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
    }
}
