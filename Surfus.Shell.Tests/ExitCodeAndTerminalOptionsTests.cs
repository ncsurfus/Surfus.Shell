using System.IO;
using System.Text;

namespace Surfus.Shell.Tests;

public class ExitCodeAndTerminalOptionsTests
{
    private const string User = "testuser";
    private const string Pass = "testpass";

    private static CancellationToken Timeout(int seconds = 10) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static async Task<string> ReadAllAsync(Stream stream, CancellationToken ct)
    {
        var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    // --- Exit Code ---

    [Fact]
    public async Task ExecCommand_ExitCode_Success()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("echo hello", Timeout());
        await ReadAllAsync(command.StandardOutput, Timeout());

        Assert.Equal(0, command.ExitCode);
    }

    [Fact]
    public async Task ExecCommand_ExitCode_Failure()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var command = await client.CreateCommandAsync(Timeout());
        await command.StartAsync("exit 1", Timeout());
        await ReadAllAsync(command.StandardOutput, Timeout());

        Assert.Equal(1, command.ExitCode);
    }

    [Fact]
    public async Task ExecCommand_ExitCode_NullBeforeCompletion()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var command = await client.CreateCommandAsync(Timeout());
        Assert.Null(command.ExitCode);
    }

    // --- Terminal Options ---

    [Fact]
    public async Task Terminal_DefaultOptions()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        // Default options (xterm 80x24) should work fine
        var terminal = await client.CreateTerminalAsync(Timeout());
        Assert.True(terminal.IsOpen);

        var buf = new byte[4096];
        var n = await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, Timeout());
        Assert.True(n > 0);
    }

    [Fact]
    public async Task Terminal_CustomOptions()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var options = new TerminalOptions
        {
            TerminalType = "xterm-256color",
            Columns = 120,
            Rows = 40,
            WidthPixels = 1920,
            HeightPixels = 1080,
        };
        var terminal = await client.CreateTerminalAsync(Timeout(), options);
        Assert.True(terminal.IsOpen);

        var buf = new byte[4096];
        var n = await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, Timeout());
        Assert.True(n > 0);
    }

    // --- Command with PTY ---

    [Fact]
    public async Task Command_RequestPseudoTerminal_BeforeStart()
    {
        await using var server = await SshTestServer.StartAsync();
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var command = await client.CreateCommandAsync(Timeout());
        await command.RequestPseudoTerminalAsync(Timeout(), new TerminalOptions { TerminalType = "vt100" });
        await command.StartAsync("echo hello", Timeout());

        var stdout = await ReadAllAsync(command.StandardOutput, Timeout());
        Assert.Contains("hello", stdout);
        Assert.Equal(0, command.ExitCode);
    }

    // --- Terminal Exit Code ---

    [Fact]
    public async Task Terminal_ExitCode_OnExit()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var terminal = await client.CreateTerminalAsync(Timeout());

        // Read initial prompt
        var buf = new byte[4096];
        await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, Timeout());

        // Send "exit" to trigger exit-status
        var data = Encoding.UTF8.GetBytes("exit\n");
        await terminal.StandardInput.WriteAsync(data, 0, data.Length, Timeout());
        await terminal.StandardInput.FlushAsync(Timeout());

        // Read remaining output until stream closes
        await ReadAllAsync(terminal.StandardOutput, Timeout());

        Assert.Equal(0, terminal.ExitCode);
    }
}
