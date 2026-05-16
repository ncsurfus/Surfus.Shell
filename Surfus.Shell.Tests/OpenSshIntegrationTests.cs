using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Authentication;

namespace Surfus.Shell.Tests;

[Collection("OpenSSH")]
public class OpenSshIntegrationTests
{
    private static CancellationToken Timeout(int seconds = 10) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task ConnectAndAuthenticate_PublicKey()
    {
        await using var server = await OpenSshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());

        var key = new PrivateKeyAuth(File.ReadAllText(server.PrivateKeyPath));
        await client.AuthenticateAsync(Environment.UserName, key, Timeout());

        Assert.True(client.IsConnected);
    }

    [Theory]
    [InlineData("ecdh-sha2-nistp256")]
    [InlineData("ecdh-sha2-nistp384")]
    [InlineData("ecdh-sha2-nistp521")]
    [InlineData("diffie-hellman-group14-sha256")]
    [InlineData("diffie-hellman-group16-sha512")]
    [InlineData("diffie-hellman-group-exchange-sha256")]
    public async Task KexAlgorithm(string kex)
    {
        await using var server = await OpenSshTestServer.StartAsync(kexAlgorithms: kex);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port)
        {
            Algorithms = new SshAlgorithms
            {
                KeyExchange = SshAlgorithms.DefaultKeyExchange.Where(d => d.Name == kex).ToArray()
            }
        };
        await client.ConnectAsync(Timeout());
        var key = new PrivateKeyAuth(File.ReadAllText(server.PrivateKeyPath));
        await client.AuthenticateAsync(Environment.UserName, key, Timeout());
        Assert.True(client.IsConnected);
    }

    [Theory]
    [InlineData("aes128-ctr")]
    [InlineData("aes192-ctr")]
    [InlineData("aes256-ctr")]
    [InlineData("aes128-gcm@openssh.com")]
    [InlineData("aes256-gcm@openssh.com")]
    public async Task Cipher(string cipher)
    {
        await using var server = await OpenSshTestServer.StartAsync(ciphers: cipher);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port)
        {
            Algorithms = new SshAlgorithms
            {
                Encryption = SshAlgorithms.DefaultEncryption.Where(d => d.Name == cipher).ToArray()
            }
        };
        await client.ConnectAsync(Timeout());
        var key = new PrivateKeyAuth(File.ReadAllText(server.PrivateKeyPath));
        await client.AuthenticateAsync(Environment.UserName, key, Timeout());

        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo cipher_test", Timeout());
        var ms = new MemoryStream();
        await command.StandardOutput.CopyToAsync(ms, Timeout());
        Assert.Contains("cipher_test", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Theory]
    [InlineData("hmac-sha2-256")]
    [InlineData("hmac-sha2-512")]
    [InlineData("hmac-sha2-256-etm@openssh.com")]
    [InlineData("hmac-sha2-512-etm@openssh.com")]
    public async Task Mac(string mac)
    {
        await using var server = await OpenSshTestServer.StartAsync(macs: mac);
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port)
        {
            Algorithms = new SshAlgorithms
            {
                Mac = SshAlgorithms.DefaultMac.Where(d => d.Name == mac).ToArray()
            }
        };
        await client.ConnectAsync(Timeout());
        var key = new PrivateKeyAuth(File.ReadAllText(server.PrivateKeyPath));
        await client.AuthenticateAsync(Environment.UserName, key, Timeout());

        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo mac_test", Timeout());
        var ms = new MemoryStream();
        await command.StandardOutput.CopyToAsync(ms, Timeout());
        Assert.Contains("mac_test", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public async Task LargeDataTransfer_ForcesRekey()
    {
        // OpenSSH rekeys after 1GB by default, but we can set RekeyLimit low
        await using var server = await OpenSshTestServer.StartAsync(rekeyLimit: "1M");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout(30));
        var key = new PrivateKeyAuth(File.ReadAllText(server.PrivateKeyPath));
        await client.AuthenticateAsync(Environment.UserName, key, Timeout(30));

        // Send 4MB to force multiple rekeys (limit is 1MB)
        var command = await client.CreateCommandAsync(Timeout(30));
        await command.StartAsync("head -c 4194304 /dev/zero", Timeout(30));

        long total = 0;
        var buf = new byte[32 * 1024];
        while (total < 4 * 1024 * 1024)
        {
            var n = await command.StandardOutput.ReadAsync(buf, Timeout(30));
            if (n == 0) break;
            total += n;
        }

        Assert.Equal(4 * 1024 * 1024, total);
    }

    [Fact]
    public async Task ExecCommand()
    {
        await using var server = await OpenSshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());

        var key = new PrivateKeyAuth(File.ReadAllText(server.PrivateKeyPath));
        await client.AuthenticateAsync(Environment.UserName, key, Timeout());

        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo hello", Timeout());

        var ms = new MemoryStream();
        await command.StandardOutput.CopyToAsync(ms, Timeout());
        var output = Encoding.UTF8.GetString(ms.ToArray()).Trim();

        Assert.Equal("hello", output);
    }

    [Fact]
    public async Task Terminal_EchoBack()
    {
        await using var server = await OpenSshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());

        var key = new PrivateKeyAuth(File.ReadAllText(server.PrivateKeyPath));
        await client.AuthenticateAsync(Environment.UserName, key, Timeout());

        var terminal = await client.CreateTerminalAsync(Timeout());
        await terminal.StandardInput.WriteAsync("echo test123\n"u8.ToArray(), Timeout());

        var buf = new byte[4096];
        var totalRead = 0;
        var output = "";
        while (!output.Contains("test123"))
        {
            var n = await terminal.StandardOutput.ReadAsync(buf.AsMemory(totalRead), Timeout());
            if (n == 0) break;
            totalRead += n;
            output = Encoding.UTF8.GetString(buf, 0, totalRead);
        }

        Assert.Contains("test123", output);
    }
}
