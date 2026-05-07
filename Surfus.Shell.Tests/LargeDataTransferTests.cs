using System.IO;
using System.Text;

namespace Surfus.Shell.Tests;

[Collection("Integration")]
public class LargeDataTransferTests
{
    private const string User = "testuser";
    private const string Pass = "testpass";

    private static CancellationToken Timeout(int seconds = 15) => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task ExecChannel_LargeOutput_AllDataReceived()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var command = await client.CreateCommandAsync(Timeout());

        // Generate output larger than the default window size (50000 bytes)
        await command.StartAsync("printf '%0.s.' $(seq 1 80000)", Timeout());

        var ms = new MemoryStream();
        await command.StandardOutput.CopyToAsync(ms, Timeout());

        Assert.Equal(80000, ms.Length);
    }
}
