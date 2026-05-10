using System.IO;
using System.Text;

namespace Surfus.Shell.Tests;

[Collection("Integration")]
public class ScpTests
{
    private const string User = "testuser";
    private const string Pass = "testpass";

    private static CancellationToken Timeout(int seconds = 10) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task Upload_And_Download_RoundTrip()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var scp = new ScpClient(client);
        var content = "Hello from SCP test!\n";
        var remotePath = $"/tmp/scp_test_{Guid.NewGuid():N}.txt";

        try
        {
            // Upload
            using (var uploadStream = new MemoryStream(Encoding.UTF8.GetBytes(content)))
            {
                await scp.UploadAsync(uploadStream, uploadStream.Length, remotePath, cancellationToken: Timeout());
            }

            // Download
            using var downloadStream = new MemoryStream();
            await scp.DownloadAsync(remotePath, downloadStream, Timeout());

            var downloaded = Encoding.UTF8.GetString(downloadStream.ToArray());
            Assert.Equal(content, downloaded);
        }
        finally
        {
            // Cleanup
            var cleanup = await client.CreateCommandAsync(Timeout());
            await using (cleanup)
            {
                await cleanup.StartAsync($"rm -f {remotePath}", Timeout());
                await cleanup.StandardOutput.CopyToAsync(Stream.Null, Timeout());
            }
        }
    }

    [Fact]
    public async Task Upload_Stream_WithCustomFileName()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var scp = new ScpClient(client);
        var content = "custom filename test";
        var remotePath = $"/tmp/scp_custom_{Guid.NewGuid():N}.txt";

        try
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(content)))
            {
                await scp.UploadAsync(stream, stream.Length, remotePath, "myfile.txt", cancellationToken: Timeout());
            }

            // Verify file exists and has correct content
            var cmd = await client.CreateCommandAsync(Timeout());
            await using (cmd)
            {
                await cmd.StartAsync($"cat {remotePath}", Timeout());
                var ms = new MemoryStream();
                await cmd.StandardOutput.CopyToAsync(ms, Timeout());
                Assert.Equal(content, Encoding.UTF8.GetString(ms.ToArray()));
            }
        }
        finally
        {
            var cleanup = await client.CreateCommandAsync(Timeout());
            await using (cleanup)
            {
                await cleanup.StartAsync($"rm -f {remotePath}", Timeout());
                await cleanup.StandardOutput.CopyToAsync(Stream.Null, Timeout());
            }
        }
    }
}
