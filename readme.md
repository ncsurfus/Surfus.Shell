# Surfus.Shell
Surfus.Shell is an SSH library for .NET designed to be super quick! It's been primarily designed for Cisco routers and switches, but can be used for anything.

## Goals
 - Completely asynchronous
 - Supports .NET Core and .NET Standard

## Code
    using(var client = new SshClient("127.0.0.1"))
    {
        await client.ConnectAsync("user", "pass", CancellationToken.None);
        var terminal = await client.CreateTerminalAsync(CancellationToken.None);
        terminal.WriteAsync("Hello World!", CancellationToken.None);
    }
	
## Todo
 - Create a callback function for host key validation.
 - Provide support for certificate authentication.