namespace Surfus.Shell.Tests;

public class SshIntegrationTests
{
    private const string User = "testuser";
    private const string Pass = "testpass";

    private static CancellationToken Timeout(int seconds = 10)
        => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

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
        await Assert.ThrowsAsync<Exceptions.SshInvalidCredentials>(
            () => client.AuthenticateAsync(User, "wrong", Timeout()));
    }

    [Fact]
    public async Task AuthRetry_WrongThenRight()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());

        // First attempt fails
        await Assert.ThrowsAsync<Exceptions.SshInvalidCredentials>(
            () => client.AuthenticateAsync(User, "wrong", Timeout()));

        // Second attempt succeeds without reconnecting
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
        var result = await command.ExecuteAsync("echo hello", Timeout());
        Assert.Contains("hello", result);
    }

    [Fact]
    public async Task ShellChannel_CanWriteAndRead()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var terminal = await client.CreateTerminalAsync(Timeout());
        // Just verify we can read something from the shell
        var data = await terminal.ReadAsync(Timeout());
        Assert.False(string.IsNullOrEmpty(data));
    }

    // --- Host key ---

    [Fact]
    public async Task HostKeyCallback_ReceivesKey()
    {
        await using var server = await SshTestServer.StartAsync();
        byte[]? receivedKey = null;
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        client.HostKeyCallback = key => { receivedKey = key; return true; };
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.NotNull(receivedKey);
        Assert.True(receivedKey!.Length > 0);
    }

    [Fact]
    public async Task HostKeyCallback_RejectDisconnects()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        client.HostKeyCallback = _ => false;
        await Assert.ThrowsAsync<Exceptions.SshException>(
            () => client.ConnectAsync(Timeout()));
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
    // group18-sha512 not tested: Go's x/crypto/ssh doesn't implement it
    public async Task KexAlgorithm(string kex)
    {
        await using var server = await SshTestServer.StartAsync(kex: kex);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
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
        await using var server = await SshTestServer.StartAsync(ciphers: cipher);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
    }

    // --- MACs ---

    [Theory]
    [InlineData("hmac-sha2-256")]
    [InlineData("hmac-sha2-512")]
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
