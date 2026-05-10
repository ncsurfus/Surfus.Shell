using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Surfus.Shell.Tests;

[Collection("Integration")]
public class StreamConstructorTests
{
    private const string User = "testuser";
    private const string Pass = "testpass";

    private static CancellationToken Timeout(int seconds = 10) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task StreamFactory_ConnectsAndAuthenticates()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient(async ct =>
        {
            var tcp = new TcpClient();
            await tcp.ConnectAsync("127.0.0.1", server.Port, ct);
            return ((Stream)tcp.GetStream(), (Func<ValueTask>)(() => { tcp.Dispose(); return ValueTask.CompletedTask; }));
        });
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task StreamFactory_OnCloseAsyncCalledOnDispose()
    {
        await using var server = await SshTestServer.StartAsync();
        var closeCalled = 0;
        var client = new SshClient(async ct =>
        {
            var tcp = new TcpClient();
            await tcp.ConnectAsync("127.0.0.1", server.Port, ct);
            return ((Stream)tcp.GetStream(), (Func<ValueTask>)(() =>
            {
                Interlocked.Increment(ref closeCalled);
                tcp.Dispose();
                return ValueTask.CompletedTask;
            }));
        });
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        await client.DisposeAsync();

        Assert.Equal(1, closeCalled);
    }

    [Fact]
    public async Task StreamFactory_OnCloseAsyncCalledOnlyOnce_WhenConnectFails()
    {
        var closeCalled = 0;
        var client = new SshClient(ct =>
        {
            // Return a stream that will immediately close (no SSH server on the other end)
            var pair = ConnectedStreamPair();
            pair.ServerTcp.Dispose(); // close immediately to trigger failure
            return Task.FromResult<(Stream, Func<ValueTask>?)>((pair.ClientSide, () =>
            {
                Interlocked.Increment(ref closeCalled);
                pair.ClientTcp.Dispose();
                return ValueTask.CompletedTask;
            }));
        });

        await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync(Timeout()));
        await client.DisposeAsync();

        Assert.Equal(1, closeCalled);
    }

    [Fact]
    public async Task Stream_ConnectsAndAuthenticates()
    {
        await using var server = await SshTestServer.StartAsync();
        var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", server.Port);
        await using var client = new SshClient(tcp.GetStream());
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        Assert.True(client.IsConnected);
        tcp.Dispose();
    }

    [Fact]
    public async Task Stream_ExecCommand()
    {
        await using var server = await SshTestServer.StartAsync();
        var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", server.Port);
        await using var client = new SshClient(tcp.GetStream());
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());
        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo hello", Timeout());
        var ms = new MemoryStream();
        await command.StandardOutput.CopyToAsync(ms, Timeout());
        var stdout = Encoding.UTF8.GetString(ms.ToArray());
        Assert.Contains("hello", stdout);
        tcp.Dispose();
    }

    [Fact]
    public void NullStreamFactory_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SshClient((Func<CancellationToken, Task<(Stream, Func<ValueTask>?)>>)null!));
    }

    [Fact]
    public void NullStream_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new SshClient((Stream)null!));
    }

    [Fact]
    public async Task Hostname_ConnectionRefused_DisposesCleanly()
    {
        // Use a port that is not listening to trigger connection refused
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        await using var client = new SshClient("127.0.0.1", (ushort)port);
        await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync(Timeout()));
    }

    [Fact]
    public async Task StreamFactory_CancellationDuringRead_ThrowsOperationCanceled()
    {
        // Provide a stream that never sends data — cancellation should fire
        var client = new SshClient(ct =>
        {
            var pair = ConnectedStreamPair();
            return Task.FromResult<(Stream, Func<ValueTask>?)>((pair.ClientSide, () =>
            {
                pair.ClientTcp.Dispose();
                pair.ServerTcp.Dispose();
                return ValueTask.CompletedTask;
            }));
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ConnectAsync(cts.Token));
        await client.DisposeAsync();
    }

    private static (NetworkStream ClientSide, NetworkStream ServerSide, TcpClient ClientTcp, TcpClient ServerTcp) ConnectedStreamPair()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var clientTcp = new TcpClient();
        clientTcp.Connect(IPAddress.Loopback, port);
        var serverTcp = listener.AcceptTcpClient();
        listener.Stop();
        return (clientTcp.GetStream(), serverTcp.GetStream(), clientTcp, serverTcp);
    }
}
