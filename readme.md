# Surfus.Shell

Surfus.Shell is an SSH client library for .NET.

## Features

- Fully asynchronous API
- Terminal sessions, command execution, and SCP file transfers
- Local port forwarding (direct-tcpip)
- SSH agent authentication
- Private key authentication
- Keyboard-interactive authentication
- Host key verification callback
- Low-level channel API for custom SSH extensions

## Installation

```
dotnet add package Surfus.Shell
```

## Quick Start

```csharp
await using var client = new SshClient("192.168.1.1");
await client.ConnectAsync(cancellationToken);
await client.AuthenticateAsync("admin", "password", cancellationToken);

var terminal = await client.CreateTerminalAsync(cancellationToken);
await terminal.StandardInput.WriteAsync("show version\n"u8.ToArray(), cancellationToken);
```

## Examples

### Connect and Authenticate

```csharp
await using var client = new SshClient("host", 22);
await client.ConnectAsync(ct);

// Password authentication
await client.AuthenticateAsync("user", "pass", ct);

// Keyboard-interactive
await client.AuthenticateAsync("user", (prompt, ct) => Task.FromResult("password"), ct);

// SSH agent
var agent = await SshAgentClient.ConnectAsync(ct);
await client.AuthenticateAsync("user", agent, ct);

// Private key
var key = PrivateKeyAuth.FromFile("/path/to/key");
await client.AuthenticateAsync("user", key, ct);
```

### Terminal Session

```csharp
var terminal = await client.CreateTerminalAsync(ct);

// Write to stdin
await terminal.StandardInput.WriteAsync("ls -la\n"u8.ToArray(), ct);

// Read from stdout
var buf = new byte[4096];
var n = await terminal.StandardOutput.ReadAsync(buf, ct);
var output = Encoding.UTF8.GetString(buf, 0, n);
```

### Execute a Command

```csharp
var command = await client.CreateCommandAsync(ct);
await command.StartAsync("echo hello", ct);

var result = new MemoryStream();
await command.StandardOutput.CopyToAsync(result, ct);
// result contains "hello\n"

// Exit code is available after the channel closes
var exitCode = command.ExitCode;
```

### Local Port Forwarding

```csharp
// Forward local port 8080 through SSH to remote-db:5432
await client.ForwardLocalPortAsync(8080, "remote-db", 5432, ct);
```

### Direct TCP/IP Channel

```csharp
// Open a single forwarded connection
await using var channel = await client.CreateDirectTcpIpChannelAsync("10.0.0.5", 80, ct);

await channel.StandardInput.WriteAsync("GET / HTTP/1.0\r\n\r\n"u8.ToArray(), ct);
var response = new MemoryStream();
await channel.StandardOutput.CopyToAsync(response, ct);
```

### SCP File Transfer

```csharp
var scp = new ScpClient(client);

// Upload
await scp.UploadAsync("/local/file.txt", "/remote/file.txt", cancellationToken: ct);

// Download
await scp.DownloadAsync("/remote/file.txt", "/local/file.txt", ct);
```

### Host Key Verification

```csharp
var client = new SshClient("host")
{
    HostKeyCallback = async (hostKey, ct) =>
    {
        // Verify the host key and return true to accept
        return true;
    }
};
```

### Banner Callback

```csharp
var client = new SshClient("host")
{
    OnBanner = banner => Console.WriteLine($"Server banner: {banner}")
};
```

### Low-Level Channel API

For custom channel types or advanced use cases:

```csharp
// Open a raw session channel
var channel = await client.OpenChannelAsync(new ChannelOpenSession(), ct);

// Send custom requests
await channel.RequestAsync(new ChannelRequestSubsystem(channel.ServerId, true, "sftp"), ct);

// Use the channel streams
await channel.StandardInput.WriteAsync(data, ct);

// Or construct higher-level wrappers manually
var terminal = new SshTerminal(channel, new TerminalOptions { Columns = 120, Rows = 40 });
await terminal.RequestAsync(ct);
```

### Custom Stream Transport

```csharp
// Use an existing stream (e.g., over a proxy)
await using var client = new SshClient(myStream);

// Or use a factory for reconnectable transports
await using var client = new SshClient(async ct =>
{
    var tcp = new TcpClient();
    await tcp.ConnectAsync("host", 22, ct);
    return (tcp.GetStream(), () => { tcp.Dispose(); return ValueTask.CompletedTask; });
});
```
