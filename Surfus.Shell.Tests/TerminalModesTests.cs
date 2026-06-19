using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace Surfus.Shell.Tests;

public class TerminalOptionsTests
{
    [Fact]
    public void TerminalMode_Echo_SetsCorrectOpcodeAndValue()
    {
        Assert.Equal(new TerminalMode(53, 0), TerminalMode.Echo(false));
        Assert.Equal(new TerminalMode(53, 1), TerminalMode.Echo(true));
    }

    [Fact]
    public void TerminalMode_Icrnl_SetsCorrectOpcodeAndValue()
    {
        Assert.Equal(new TerminalMode(63, 0), TerminalMode.Icrnl(false));
        Assert.Equal(new TerminalMode(63, 1), TerminalMode.Icrnl(true));
    }

    [Fact]
    public void TerminalMode_Onlcr_SetsCorrectOpcodeAndValue()
    {
        Assert.Equal(new TerminalMode(72, 0), TerminalMode.Onlcr(false));
        Assert.Equal(new TerminalMode(72, 1), TerminalMode.Onlcr(true));
    }

    [Fact]
    public void BuildTerminalModes_NoModesSet_ReturnsEmpty()
    {
        var options = new TerminalOptions();
        Assert.True(options.BuildTerminalModes().IsEmpty);
    }

    [Fact]
    public void BuildTerminalModes_EchoFalse_EncodesCorrectly()
    {
        var options = new TerminalOptions { Echo = false };
        var modes = options.BuildTerminalModes().ToArray();

        Assert.Equal(6, modes.Length);
        Assert.Equal(53, modes[0]);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(modes.AsSpan(1)));
        Assert.Equal(0, modes[5]);
    }

    [Fact]
    public void BuildTerminalModes_EchoTrue_EncodesCorrectly()
    {
        var options = new TerminalOptions { Echo = true };
        var modes = options.BuildTerminalModes().ToArray();

        Assert.Equal(6, modes.Length);
        Assert.Equal(53, modes[0]);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(modes.AsSpan(1)));
        Assert.Equal(0, modes[5]);
    }

    [Fact]
    public void BuildTerminalModes_InputCrTranslationFalse_EncodesCorrectly()
    {
        var options = new TerminalOptions { InputCarriageReturnTranslation = false };
        var modes = options.BuildTerminalModes().ToArray();

        Assert.Equal(6, modes.Length);
        Assert.Equal(63, modes[0]);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(modes.AsSpan(1)));
        Assert.Equal(0, modes[5]);
    }

    [Fact]
    public void BuildTerminalModes_OutputNlTranslationTrue_EncodesCorrectly()
    {
        var options = new TerminalOptions { OutputNewlineTranslation = true };
        var modes = options.BuildTerminalModes().ToArray();

        Assert.Equal(6, modes.Length);
        Assert.Equal(72, modes[0]);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(modes.AsSpan(1)));
        Assert.Equal(0, modes[5]);
    }

    [Fact]
    public void BuildTerminalModes_MultipleModesSet_AllEncodedInOrder()
    {
        var options = new TerminalOptions
        {
            Echo = false,
            InputCarriageReturnTranslation = true,
            OutputNewlineTranslation = false,
        };
        var modes = options.BuildTerminalModes().ToArray();

        // 3 modes × 5 bytes + 1 TTY_OP_END = 16
        Assert.Equal(16, modes.Length);

        // First mode: ECHO = 0
        Assert.Equal(53, modes[0]);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(modes.AsSpan(1)));

        // Second mode: ICRNL = 1
        Assert.Equal(63, modes[5]);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(modes.AsSpan(6)));

        // Third mode: ONLCR = 0
        Assert.Equal(72, modes[10]);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(modes.AsSpan(11)));

        // Terminator
        Assert.Equal(0, modes[15]);
    }

    [Fact]
    public void BuildTerminalModes_RawTerminalModesSet_ReturnedVerbatim()
    {
        var options = new TerminalOptions
        {
            RawTerminalModes = new[] { TerminalMode.Echo(false) },
            Echo = true, // should be ignored
        };
        var modes = options.BuildTerminalModes().ToArray();
        Assert.Equal(new byte[] { 53, 0, 0, 0, 0, 0 }, modes);
    }

    [Fact]
    public void BuildTerminalModes_RawTerminalModesEmpty_ReturnsEmpty()
    {
        var options = new TerminalOptions
        {
            RawTerminalModes = Array.Empty<TerminalMode>(),
            Echo = true, // should be ignored — Raw takes precedence even when empty
        };
        Assert.True(options.BuildTerminalModes().IsEmpty);
    }

    [Fact]
    public void BuildTerminalModes_RawTerminalModes_CustomOpcode()
    {
        var options = new TerminalOptions
        {
            RawTerminalModes = new[] { new TerminalMode(200, 42) },
        };
        var modes = options.BuildTerminalModes().ToArray();
        Assert.Equal(6, modes.Length);
        Assert.Equal(200, modes[0]);
        Assert.Equal(42u, BinaryPrimitives.ReadUInt32BigEndian(modes.AsSpan(1)));
        Assert.Equal(0, modes[5]);
    }
}

/// <summary>
/// Integration tests that verify terminal modes are accepted by a real SSH server.
/// </summary>
[Collection("Integration")]
public class TerminalModeIntegrationTests
{
    private const string User = "testuser";
    private const string Pass = "testpass";

    private static CancellationToken Timeout(int seconds = 10) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static async Task<string> ReadInitialOutput(SshTerminal terminal, CancellationToken ct)
    {
        var buf = new byte[4096];
        var n = await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, ct);
        return Encoding.UTF8.GetString(buf, 0, n);
    }

    [Fact]
    public async Task Terminal_NoModes_ServerReceivesEmptyModes()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var terminal = await client.CreateTerminalAsync(Timeout());
        var output = await ReadInitialOutput(terminal, Timeout());

        Assert.True(terminal.IsOpen);
        Assert.DoesNotContain("TERMMODES:", output);
        Assert.Contains("$ ", output);
    }

    [Fact]
    public async Task Terminal_EchoFalse_ServerReceivesCorrectModes()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var options = new TerminalOptions { Echo = false };
        var terminal = await client.CreateTerminalAsync(Timeout(), options);
        var output = await ReadInitialOutput(terminal, Timeout());

        // Server should echo back: opcode 53 (0x35), value 0x00000000, TTY_OP_END 0x00
        Assert.Contains("TERMMODES:350000000000", output);
    }

    [Fact]
    public async Task Terminal_MultipleModesSet_ServerReceivesAll()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var options = new TerminalOptions
        {
            Echo = false,
            InputCarriageReturnTranslation = false,
            OutputNewlineTranslation = true,
        };
        var terminal = await client.CreateTerminalAsync(Timeout(), options);
        var output = await ReadInitialOutput(terminal, Timeout());

        // ECHO(53)=0, ICRNL(63)=0, ONLCR(72)=1, TTY_OP_END
        // Hex: 35 00000000 3f 00000000 48 00000001 00
        Assert.Contains("TERMMODES:35000000003f00000000480000000100", output);
    }

    [Fact]
    public async Task Terminal_RawTerminalModes_ServerReceivesVerbatim()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var options = new TerminalOptions
        {
            RawTerminalModes = new[] { TerminalMode.Echo(false) },
        };
        var terminal = await client.CreateTerminalAsync(Timeout(), options);
        var output = await ReadInitialOutput(terminal, Timeout());

        Assert.Contains("TERMMODES:350000000000", output);
    }

    [Fact]
    public async Task Command_WithTerminalModes_ServerReceivesModes()
    {
        await using var server = await SshTestServer.StartAsync(shellMode: "echo");
        await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
        await client.ConnectAsync(Timeout());
        await client.AuthenticateAsync(User, Pass, Timeout());

        var options = new TerminalOptions { Echo = true };
        var terminal = await client.CreateTerminalAsync(Timeout(), options);
        var output = await ReadInitialOutput(terminal, Timeout());

        // ECHO(53)=1, TTY_OP_END
        Assert.Contains("TERMMODES:350000000100", output);
    }
}
