using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Surfus.Shell.Tests;

[Collection("Integration")]
public class PortForwardingTests
{
    private const string User = "testuser";
    private const string Pass = "testpass";

    private static CancellationToken Timeout(int seconds = 10) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task CreateDirectTcpIpChannel_ForwardsData()
    {
        // Start a local TCP echo server
        using var echoServer = StartEchoServer(out var echoPort);

        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        // Open a direct-tcpip channel through SSH to the echo server
        await using var channel = await client.CreateDirectTcpIpChannelAsync(
            "127.0.0.1", (uint)echoPort, Timeout());

        // Send data through the channel
        var message = "hello forwarding\n"u8.ToArray();
        await channel.Stdin.WriteAsync(message, Timeout());
        await channel.Stdin.FlushAsync(Timeout());

        // Read the echoed response
        var buf = new byte[1024];
        var n = await channel.Stdout.ReadAsync(buf, Timeout());
        var response = Encoding.UTF8.GetString(buf, 0, n);

        Assert.Equal("hello forwarding\n", response);
    }

    [Fact]
    public async Task ForwardLocalPort_ForwardsConnections()
    {
        // Start a local TCP echo server
        using var echoServer = StartEchoServer(out var echoPort);

        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        // Find a free port for the forwarder
        var forwardPort = GetFreePort();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var forwardTask = client.ForwardLocalPortAsync(
            forwardPort, "127.0.0.1", (uint)echoPort, cts.Token);

        // Give the listener a moment to start
        await Task.Delay(100);

        // Connect to the forwarded port
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, forwardPort, cts.Token);
        var stream = tcp.GetStream();

        var message = "port forward test\n"u8.ToArray();
        await stream.WriteAsync(message, cts.Token);
        await stream.FlushAsync(cts.Token);

        var buf = new byte[1024];
        var n = await stream.ReadAsync(buf, cts.Token);
        var response = Encoding.UTF8.GetString(buf, 0, n);

        Assert.Equal("port forward test\n", response);

        // Cancel to stop the forwarder
        cts.Cancel();
        await forwardTask;
    }

    private static TcpListener StartEchoServer(out int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        port = ((IPEndPoint)listener.LocalEndpoint).Port;

        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    var tcp = await listener.AcceptTcpClientAsync();
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var s = tcp.GetStream();
                            await s.CopyToAsync(s);
                        }
                        catch { }
                        finally { tcp.Dispose(); }
                    });
                }
            }
            catch { }
        });

        return listener;
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
