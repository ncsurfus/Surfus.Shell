using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Authentication;
using Surfus.Shell.Cisco;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;
using Surfus.Shell.Signing;

namespace Surfus.Shell.Tests;

public class BugFixTests
{
    // Fix #5: ReadBigInteger(byte[]) should reverse before creating BigInteger even when high bit is set
    [Fact]
    public void ReadBigInteger_HighBitSet_ReturnsCorrectValue()
    {
        // Big-endian representation of 0x80 = 128
        byte[] buffer = [0x80];
        var result = ByteReader.ReadBigInteger(buffer);
        Assert.Equal(new BigInteger(128), result);
    }

    [Fact]
    public void ReadBigInteger_HighBitSet_MultiByteBuffer()
    {
        // Big-endian representation of 0xFF01 = 65281
        byte[] buffer = [0xFF, 0x01];
        var result = ByteReader.ReadBigInteger(buffer);
        Assert.Equal(new BigInteger(65281), result);
    }

    [Fact]
    public void ReadBigInteger_LowBitPath_StillWorks()
    {
        // Big-endian representation of 0x01 = 1
        byte[] buffer = [0x01];
        var result = ByteReader.ReadBigInteger(buffer);
        Assert.Equal(BigInteger.One, result);
    }

    // Fix #6: ByteReader bounds checking
    [Fact]
    public void ReadByte_EmptyBuffer_Throws()
    {
        var reader = new ByteReader(Array.Empty<byte>());
        var ex = Assert.Throws<SshException>(() => reader.ReadByte());
        Assert.Contains("Malformed packet", ex.Message);
    }

    [Fact]
    public void ReadUInt32_TooShortBuffer_Throws()
    {
        var reader = new ByteReader(new byte[] { 0x01, 0x02 });
        Assert.Throws<SshException>(() => reader.ReadUInt32());
    }

    [Fact]
    public void ReadBoolean_EmptyBuffer_Throws()
    {
        var reader = new ByteReader(Array.Empty<byte>());
        Assert.Throws<SshException>(() => reader.ReadBoolean());
    }

    [Fact]
    public void Read_TooShortBuffer_Throws()
    {
        var reader = new ByteReader(new byte[] { 0x01 });
        Assert.Throws<SshException>(() => reader.Read(5));
    }

    [Fact]
    public void ReadString_TruncatedPayload_Throws()
    {
        // Length says 10 bytes but only 2 bytes of payload follow
        byte[] buffer = [0x00, 0x00, 0x00, 0x0A, 0x41, 0x42];
        var reader = new ByteReader(buffer);
        Assert.Throws<SshException>(() => reader.ReadString());
    }

    // Fix #11: UaRequest keyboard-interactive constructor should assign language/subMethods
    [Fact]
    public void UaRequest_KeyboardInteractive_AssignsLanguageAndSubmethods()
    {
        var request = new UaRequest("user", "ssh-connection", "keyboard-interactive", "en-US", "pam");
        Assert.Equal("en-US", request.Language);
        Assert.Equal("pam", request.Submethods);
    }

    // Fix #12: Integer overflow in ByteReader string methods
    [Fact]
    public void ReadString_OverflowLength_Throws()
    {
        // uint 0x80000000 > int.MaxValue, cast to int gives negative
        byte[] buffer = [0x80, 0x00, 0x00, 0x00];
        var reader = new ByteReader(buffer);
        Assert.Throws<SshException>(() => reader.ReadString());
    }

    [Fact]
    public void ReadAsciiString_OverflowLength_Throws()
    {
        byte[] buffer = [0x80, 0x00, 0x00, 0x00];
        var reader = new ByteReader(buffer);
        Assert.Throws<SshException>(() => reader.ReadAsciiString());
    }

    [Fact]
    public void ReadBinaryString_OverflowLength_Throws()
    {
        byte[] buffer = [0x80, 0x00, 0x00, 0x00];
        var reader = new ByteReader(buffer);
        Assert.Throws<SshException>(() => reader.ReadBinaryString());
    }

    // Fix #17: SshAuthentication should filter messages by type
    [Fact]
    public async Task SshAuthentication_FiltersNonAuthMessages()
    {
        var auth = new SshAuthentication(() => new byte[32]);
        var sent = new List<IClientMessage>();
        auth.OnSend = (msg, ct) =>
        {
            sent.Add(msg);
            return Task.CompletedTask;
        };

        // Start login - it will wait for ServiceAccept
        var loginTask = auth.LoginAsync("user", new Surfus.Shell.Authentication.PasswordAuth("pass"), CancellationToken.None);

        // Send a channel message (type 90+) - should be ignored
        var channelBuffer = new byte[10];
        ByteWriter.WriteUint(channelBuffer.AsSpan(0), 5);
        channelBuffer[4] = 0;
        channelBuffer[5] = 90; // SSH_MSG_CHANNEL_OPEN_CONFIRMATION - not in auth range
        var channelPacket = new SshPacket(channelBuffer, packetStart: 0, packetLength: 6);
        await auth.ProcessMessageAsync(new MessageEvent(channelPacket));

        // Send a kex message (type 20) - should be ignored
        var kexBuffer = new byte[10];
        ByteWriter.WriteUint(kexBuffer.AsSpan(0), 5);
        kexBuffer[4] = 0;
        kexBuffer[5] = 20; // SSH_MSG_KEXINIT - not in auth range
        var kexPacket = new SshPacket(kexBuffer, packetStart: 0, packetLength: 6);
        await auth.ProcessMessageAsync(new MessageEvent(kexPacket));

        // Now send the real ServiceAccept (type 6) - should be delivered
        var acceptBuffer = new byte[10];
        ByteWriter.WriteUint(acceptBuffer.AsSpan(0), 5);
        acceptBuffer[4] = 0;
        acceptBuffer[5] = 6; // SSH_MSG_SERVICE_ACCEPT
        var acceptPacket = new SshPacket(acceptBuffer, packetStart: 0, packetLength: 6);
        await auth.ProcessMessageAsync(new MessageEvent(acceptPacket));

        // Send auth success (type 52) - should be delivered
        var successBuffer = new byte[10];
        ByteWriter.WriteUint(successBuffer.AsSpan(0), 5);
        successBuffer[4] = 0;
        successBuffer[5] = 52; // SSH_MSG_USERAUTH_SUCCESS
        var successPacket = new SshPacket(successBuffer, packetStart: 0, packetLength: 6);
        await auth.ProcessMessageAsync(new MessageEvent(successPacket));

        // Login should complete successfully (non-auth messages were ignored)
        await loginTask;
    }

    // Fix #20: UaInfoRequest rejects excessive prompt count
    [Fact]
    public void UaInfoRequest_TooManyPrompts_Throws()
    {
        // Build a packet: msg_type + 3 empty strings (name, instruction, language) + uint32 prompt count
        var pos = 5;
        var buffer = new byte[5 + 1 + 4 + 4 + 4 + 4]; // header + type + 3 empty strings + uint32
        buffer[4] = 0; // padding
        buffer[pos++] = (byte)MessageType.SSH_MSG_USERAUTH_INFO_REQUEST;
        // name (empty string: length 0)
        pos += 4;
        // instruction (empty string)
        pos += 4;
        // language (empty string)
        pos += 4;
        // prompt count = 101
        buffer[pos++] = 0;
        buffer[pos++] = 0;
        buffer[pos++] = 0;
        buffer[pos++] = 101;

        var packet = new SshPacket(buffer, packetStart: 0, packetLength: pos);
        var msgEvent = new MessageEvent(packet);
        var ex = Assert.Throws<SshException>(() =>
        {
            _ = new MessageViews.UserAuth.UserAuthInfoRequestView(msgEvent.Payload);
        });
        Assert.Contains("Too many prompts", ex.Message);
    }

    // Fix #34: ChannelStream ReadAsync validates arguments
    [Fact]
    public async Task ChannelStream_ReadAsync_NullBuffer_Throws()
    {
        using var stream = new ChannelStream();
        await Assert.ThrowsAsync<ArgumentNullException>(() => stream.ReadAsync(null!, 0, 1, CancellationToken.None));
    }

    [Fact]
    public async Task ChannelStream_ReadAsync_NegativeOffset_Throws()
    {
        using var stream = new ChannelStream();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => stream.ReadAsync(new byte[10], -1, 1, CancellationToken.None));
    }

    [Fact]
    public async Task ChannelStream_ReadAsync_NegativeCount_Throws()
    {
        using var stream = new ChannelStream();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => stream.ReadAsync(new byte[10], 0, -1, CancellationToken.None));
    }

    [Fact]
    public async Task ChannelStream_ReadAsync_OffsetPlusCountExceedsBuffer_Throws()
    {
        using var stream = new ChannelStream();
        await Assert.ThrowsAsync<ArgumentException>(() => stream.ReadAsync(new byte[10], 5, 6, CancellationToken.None));
    }

    // Fix #37: LoginAsync with empty methods list throws
    [Fact]
    public async Task LoginAsync_EmptyMethodsList_ThrowsArgumentException()
    {
        var auth = new SshAuthentication(() => ReadOnlyMemory<byte>.Empty);
        await Assert.ThrowsAsync<ArgumentException>(() => auth.LoginAsync("user", Array.Empty<IAuthMethod>(), CancellationToken.None));
    }

    [Fact]
    public async Task LoginAsync_NullMethodsList_ThrowsArgumentException()
    {
        var auth = new SshAuthentication(() => ReadOnlyMemory<byte>.Empty);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            auth.LoginAsync("user", (IReadOnlyList<IAuthMethod>)null!, CancellationToken.None)
        );
    }

    // Fix #38: SshDss validates blob is 40 bytes
    [Fact]
    public void SshDss_VerifySignature_InvalidBlobLength_ReturnsFalse()
    {
        // Build a minimal valid DSS public key
        var keyWriter = new ByteWriter(4 + 7 + 4 + 1 + 4 + 1 + 4 + 1 + 4 + 2);
        keyWriter.WriteString("ssh-dss");
        keyWriter.WriteBinaryString((ReadOnlySpan<byte>)new byte[] { 0x07 }); // P
        keyWriter.WriteBinaryString((ReadOnlySpan<byte>)new byte[] { 0x05 }); // Q
        keyWriter.WriteBinaryString((ReadOnlySpan<byte>)new byte[] { 0x03 }); // G
        keyWriter.WriteBinaryString((ReadOnlySpan<byte>)new byte[] { 0x01, 0x02 }); // Y

        var dss = new Surfus.Shell.Signing.SshDss(keyWriter.Bytes);

        // Build a signature with wrong blob length (20 bytes instead of 40)
        var sigWriter = new ByteWriter(4 + 7 + 4 + 20);
        sigWriter.WriteString("ssh-dss");
        sigWriter.WriteBinaryString((ReadOnlySpan<byte>)new byte[20]); // wrong: should be 40

        var result = dss.VerifySignature(new byte[] { 1, 2, 3 }, sigWriter.Bytes);
        Assert.False(result);
    }
}
