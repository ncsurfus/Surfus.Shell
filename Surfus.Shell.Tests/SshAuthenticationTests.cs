using Surfus.Shell;
using Surfus.Shell.Authentication;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Tests;

public class SshAuthenticationTests
{
    private readonly List<IClientMessage> _sent = new();

    private Task FakeSend(IClientMessage message, CancellationToken ct)
    {
        _sent.Add(message);
        return Task.CompletedTask;
    }

    private SshAuthentication CreateAuth()
    {
        var auth = new SshAuthentication(() => new byte[32]);
        auth.OnSend = FakeSend;
        return auth;
    }

    /// <summary>
    /// Builds a MessageEvent for a given message type. For types that need
    /// no payload parsing (Success, Failure), this is sufficient.
    /// </summary>
    private static MessageEvent FakeMessage(MessageType type)
    {
        // Build minimal packet: [0..3]=packetSize, [4]=paddingLen, [5]=messageType
        var buffer = new byte[10];
        ByteWriter.WriteUint(buffer.AsSpan(0), 5);
        buffer[4] = 0;
        buffer[5] = (byte)type;
        var packet = new SshPacket(buffer, packetStart: 0, packetLength: 6);
        return new MessageEvent(packet);
    }

    [Fact]
    public async Task Password_Success()
    {
        var auth = CreateAuth();
        var task = auth.LoginAsync("user", new PasswordAuth("pass"), CancellationToken.None);

        // Simulate: server sends ServiceAccept, then Success
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_SUCCESS));

        await task;

        // Should have sent: ServiceRequest, then UaRequest(password)
        Assert.Equal(2, _sent.Count);
        Assert.Equal(MessageType.SSH_MSG_SERVICE_REQUEST, _sent[0].Type);
        Assert.Equal(MessageType.SSH_MSG_USERAUTH_REQUEST, _sent[1].Type);
    }

    [Fact]
    public async Task Password_Failure_Throws()
    {
        var auth = CreateAuth();
        var task = auth.LoginAsync("user", new PasswordAuth("wrong"), CancellationToken.None);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_FAILURE));

        await Assert.ThrowsAsync<SshInvalidCredentials>(() => task);
    }

    [Fact]
    public async Task ServiceAccepted_NotResentOnRetry()
    {
        var auth = CreateAuth();

        // First attempt: fails
        var task1 = auth.LoginAsync("user", new PasswordAuth("wrong"), CancellationToken.None);
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_FAILURE));
        await Assert.ThrowsAsync<SshInvalidCredentials>(() => task1);

        _sent.Clear();

        // Second attempt: should NOT send ServiceRequest again
        var task2 = auth.LoginAsync("user", new PasswordAuth("right"), CancellationToken.None);
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_SUCCESS));
        await task2;

        // Only the auth request, no service request
        Assert.Single(_sent);
        Assert.Equal(MessageType.SSH_MSG_USERAUTH_REQUEST, _sent[0].Type);
    }

    [Fact]
    public async Task MultipleMethodsTried_FirstFails_SecondSucceeds()
    {
        var auth = CreateAuth();
        var methods = new List<IAuthMethod>
        {
            new PasswordAuth("wrong"),
            new PasswordAuth("right"),
        };

        var task = auth.LoginAsync("user", methods, CancellationToken.None);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        // First method fails
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_FAILURE));
        // Second method succeeds
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_SUCCESS));

        await task;

        // ServiceRequest + first UaRequest + second UaRequest
        Assert.Equal(3, _sent.Count);
    }

    [Fact]
    public async Task MultipleMethodsTried_AllFail_Throws()
    {
        var auth = CreateAuth();
        var methods = new List<IAuthMethod>
        {
            new PasswordAuth("wrong1"),
            new PasswordAuth("wrong2"),
        };

        var task = auth.LoginAsync("user", methods, CancellationToken.None);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_FAILURE));
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_FAILURE));

        await Assert.ThrowsAsync<SshInvalidCredentials>(() => task);
    }

    [Fact]
    public async Task KeyboardInteractive_HandlesMessage60()
    {
        string? receivedPrompt = null;
        var method = new KeyboardInteractiveAuth((prompt, ct) =>
        {
            receivedPrompt = prompt;
            return Task.FromResult("mypassword");
        });

        var auth = CreateAuth();
        var task = auth.LoginAsync("user", method, CancellationToken.None);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));

        // Simulate INFO_REQUEST (message 60) with a prompt
        await auth.ProcessMessageAsync(FakeInfoRequest("Password: "));

        // Then success
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_SUCCESS));

        await task;

        Assert.Equal("Password: ", receivedPrompt);
        // ServiceRequest + keyboard-interactive request + info response
        Assert.Equal(3, _sent.Count);
    }

    [Fact]
    public async Task Banner_InvokedAndSkipped()
    {
        string? receivedBanner = null;
        var auth = CreateAuth();
        auth.OnBanner = b => receivedBanner = b;

        var task = auth.LoginAsync("user", new PasswordAuth("pass"), CancellationToken.None);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        await auth.ProcessMessageAsync(FakeBanner("Welcome!"));
        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_USERAUTH_SUCCESS));

        await task;

        Assert.Equal("Welcome!", receivedBanner);
    }

    [Fact]
    public async Task Disconnect_ThrowsDuringAuth()
    {
        var auth = CreateAuth();
        var task = auth.LoginAsync("user", new PasswordAuth("pass"), CancellationToken.None);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        await auth.ProcessMessageAsync(FakeDisconnect());

        await Assert.ThrowsAsync<SshDisconnectException>(() => task);
    }

    [Fact]
    public async Task Cancellation_Throws()
    {
        var auth = CreateAuth();
        using var cts = new CancellationTokenSource();

        var task = auth.LoginAsync("user", new PasswordAuth("pass"), cts.Token);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        // Cancel before server responds
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }

    [Fact]
    public async Task ReadLoopError_PropagatedToAuth()
    {
        var auth = CreateAuth();
        var task = auth.LoginAsync("user", new PasswordAuth("pass"), CancellationToken.None);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));

        // Simulate read loop dying with an IOException
        auth.OnError(new System.IO.IOException("connection reset"));

        var ex = await Assert.ThrowsAsync<System.IO.IOException>(() => task);
        Assert.Equal("connection reset", ex.Message);
    }

    [Fact]
    public async Task ReadLoopError_NullException_ThrowsSshException()
    {
        var auth = CreateAuth();
        var task = auth.LoginAsync("user", new PasswordAuth("pass"), CancellationToken.None);

        await auth.ProcessMessageAsync(FakeMessage(MessageType.SSH_MSG_SERVICE_ACCEPT));
        auth.OnError(null);

        await Assert.ThrowsAsync<Exceptions.SshException>(() => task);
    }

    // --- Helpers to build fake messages with payloads ---

    private static MessageEvent FakeInfoRequest(string prompt)
    {
        // INFO_REQUEST format: string name, string instruction, string language, uint32 num-prompts, [string prompt, bool echo]...
        var size = 1 // message type
            + "".GetStringSize() // name
            + "".GetStringSize() // instruction
            + "".GetStringSize() // language
            + 4 // num-prompts
            + prompt.GetStringSize() // prompt
            + 1; // echo

        var buffer = new byte[5 + size];
        buffer[4] = 0; // padding
        var pos = 5;
        buffer[pos++] = (byte)MessageType.SSH_MSG_USERAUTH_INFO_REQUEST;
        WriteString(buffer, ref pos, "");
        WriteString(buffer, ref pos, "");
        WriteString(buffer, ref pos, "");
        WriteUInt32(buffer, ref pos, 1);
        WriteString(buffer, ref pos, prompt);
        buffer[pos++] = 0; // echo = false

        var packet = new SshPacket(buffer, packetStart: 0, packetLength: pos);
        return new MessageEvent(packet);
    }

    private static MessageEvent FakeBanner(string message)
    {
        var size = 1 + message.GetStringSize() + "".GetStringSize();
        var buffer = new byte[5 + size];
        buffer[4] = 0;
        var pos = 5;
        buffer[pos++] = (byte)MessageType.SSH_MSG_USERAUTH_BANNER;
        WriteString(buffer, ref pos, message);
        WriteString(buffer, ref pos, "");

        var packet = new SshPacket(buffer, packetStart: 0, packetLength: pos);
        return new MessageEvent(packet);
    }

    private static MessageEvent FakeDisconnect()
    {
        var size = 1 + 4 + "bye".GetStringSize() + "".GetStringSize();
        var buffer = new byte[5 + size];
        buffer[4] = 0;
        var pos = 5;
        buffer[pos++] = (byte)MessageType.SSH_MSG_DISCONNECT;
        WriteUInt32(buffer, ref pos, 11); // SSH_DISCONNECT_BY_APPLICATION
        WriteString(buffer, ref pos, "bye");
        WriteString(buffer, ref pos, "");

        var packet = new SshPacket(buffer, packetStart: 0, packetLength: pos);
        return new MessageEvent(packet);
    }

    private static void WriteString(byte[] buf, ref int pos, string value)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(value);
        WriteUInt32(buf, ref pos, (uint)bytes.Length);
        Array.Copy(bytes, 0, buf, pos, bytes.Length);
        pos += bytes.Length;
    }

    private static void WriteUInt32(byte[] buf, ref int pos, uint value)
    {
        buf[pos++] = (byte)(value >> 24);
        buf[pos++] = (byte)(value >> 16);
        buf[pos++] = (byte)(value >> 8);
        buf[pos++] = (byte)value;
    }
}
