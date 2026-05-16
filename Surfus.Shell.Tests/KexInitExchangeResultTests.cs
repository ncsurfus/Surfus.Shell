using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell.Tests;

public class KexInitExchangeResultTests
{
    [Fact]
    public void SelectsFirstClientAlgorithmSupportedByServer()
    {
        var client = CreateKexInit(
            kex: ["diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"],
            hostKey: ["rsa-sha2-256", "ssh-rsa"],
            encryptionC2S: ["aes256-ctr", "aes128-ctr"],
            encryptionS2C: ["aes256-ctr", "aes128-ctr"],
            macC2S: ["hmac-sha2-256", "hmac-sha1"],
            macS2C: ["hmac-sha2-256", "hmac-sha1"],
            compressionC2S: ["none"],
            compressionS2C: ["none"]
        );

        var serverPayload = CreateServerPayload(
            kex: ["diffie-hellman-group14-sha1", "diffie-hellman-group14-sha256"],
            hostKey: ["ssh-rsa", "rsa-sha2-256"],
            encryptionC2S: ["aes128-ctr", "aes256-ctr"],
            encryptionS2C: ["aes128-ctr", "aes256-ctr"],
            macC2S: ["hmac-sha1", "hmac-sha2-256"],
            macS2C: ["hmac-sha1", "hmac-sha2-256"],
            compressionC2S: ["none"],
            compressionS2C: ["none"]
        );

        var result = CreateResult(client, serverPayload);

        // Client preference wins - first client algorithm that server also supports
        Assert.Equal("diffie-hellman-group14-sha256", result.KeyExchangeAlgorithm);
        Assert.Equal("rsa-sha2-256", result.ServerHostKeyAlgorithm);
        Assert.Equal("aes256-ctr", result.EncryptionClientToServer);
        Assert.Equal("aes256-ctr", result.EncryptionServerToClient);
        Assert.Equal("hmac-sha2-256", result.MessageAuthenticationClientToServer);
        Assert.Equal("hmac-sha2-256", result.MessageAuthenticationServerToClient);
        Assert.Equal("none", result.CompressionClientToServer);
        Assert.Equal("none", result.CompressionServerToClient);
    }

    [Fact]
    public void ThrowsWhenNoCommonAlgorithm()
    {
        var client = CreateKexInit(
            kex: ["diffie-hellman-group14-sha256"],
            hostKey: ["rsa-sha2-256"],
            encryptionC2S: ["aes256-ctr"],
            encryptionS2C: ["aes256-ctr"],
            macC2S: ["hmac-sha2-256"],
            macS2C: ["hmac-sha2-256"],
            compressionC2S: ["none"],
            compressionS2C: ["none"]
        );

        var serverPayload = CreateServerPayload(
            kex: ["diffie-hellman-group1-sha1"], // No overlap
            hostKey: ["rsa-sha2-256"],
            encryptionC2S: ["aes256-ctr"],
            encryptionS2C: ["aes256-ctr"],
            macC2S: ["hmac-sha2-256"],
            macS2C: ["hmac-sha2-256"],
            compressionC2S: ["none"],
            compressionS2C: ["none"]
        );

        Assert.Throws<SshException>(() => CreateResult(client, serverPayload));
    }

    [Fact]
    public void SingleMatchingAlgorithm_Selected()
    {
        var client = CreateKexInit(
            kex: ["diffie-hellman-group14-sha1"],
            hostKey: ["ssh-rsa"],
            encryptionC2S: ["aes128-ctr"],
            encryptionS2C: ["aes128-ctr"],
            macC2S: ["hmac-sha1"],
            macS2C: ["hmac-sha1"],
            compressionC2S: ["none"],
            compressionS2C: ["none"]
        );

        var serverPayload = CreateServerPayload(
            kex: ["diffie-hellman-group14-sha1"],
            hostKey: ["ssh-rsa"],
            encryptionC2S: ["aes128-ctr"],
            encryptionS2C: ["aes128-ctr"],
            macC2S: ["hmac-sha1"],
            macS2C: ["hmac-sha1"],
            compressionC2S: ["none"],
            compressionS2C: ["none"]
        );

        var result = CreateResult(client, serverPayload);
        Assert.Equal("diffie-hellman-group14-sha1", result.KeyExchangeAlgorithm);
        Assert.Equal("aes128-ctr", result.EncryptionClientToServer);
    }

    [Fact]
    public void StoresClientAndServerKexInit()
    {
        var client = CreateKexInit(
            kex: ["diffie-hellman-group14-sha1"],
            hostKey: ["ssh-rsa"],
            encryptionC2S: ["aes128-ctr"],
            encryptionS2C: ["aes128-ctr"],
            macC2S: ["hmac-sha1"],
            macS2C: ["hmac-sha1"],
            compressionC2S: ["none"],
            compressionS2C: ["none"]
        );

        var serverPayload = CreateServerPayload(
            kex: ["diffie-hellman-group14-sha1"],
            hostKey: ["ssh-rsa"],
            encryptionC2S: ["aes128-ctr"],
            encryptionS2C: ["aes128-ctr"],
            macC2S: ["hmac-sha1"],
            macS2C: ["hmac-sha1"],
            compressionC2S: ["none"],
            compressionS2C: ["none"]
        );

        var result = CreateResult(client, serverPayload);
        Assert.Equal(client.Bytes.Length, result.ClientBytes.Length);
        Assert.True(result.ServerBytes.Length > 0);
    }

    private static KexInit CreateKexInit(
        string[] kex,
        string[] hostKey,
        string[] encryptionC2S,
        string[] encryptionS2C,
        string[] macC2S,
        string[] macS2C,
        string[] compressionC2S,
        string[] compressionS2C
    )
    {
        // Build a KexInit by serializing and deserializing through a packet
        var kexInit = new KexInit(new SshAlgorithms());

        // We can't easily set properties on KexInit since they're get-only.
        // Instead, build a wire-format packet and parse it.
        var size =
            1 // message type
            + 16 // random bytes
            + GetNameListWireSize(kex)
            + GetNameListWireSize(hostKey)
            + GetNameListWireSize(encryptionC2S)
            + GetNameListWireSize(encryptionS2C)
            + GetNameListWireSize(macC2S)
            + GetNameListWireSize(macS2C)
            + GetNameListWireSize(compressionC2S)
            + GetNameListWireSize(compressionS2C)
            + GetNameListWireSize([]) // languages c2s
            + GetNameListWireSize([]) // languages s2c
            + 1 // first_kex_packet_follows
            + 4; // reserved

        var buffer = new byte[5 + size]; // 5 = packet_length(4) + padding_length(1)
        buffer[4] = 0; // padding length
        buffer[5] = (byte)Messages.MessageType.SSH_MSG_KEXINIT;

        var pos = 6;
        // Random bytes (16)
        pos += 16;

        WriteNameList(buffer, ref pos, kex);
        WriteNameList(buffer, ref pos, hostKey);
        WriteNameList(buffer, ref pos, encryptionC2S);
        WriteNameList(buffer, ref pos, encryptionS2C);
        WriteNameList(buffer, ref pos, macC2S);
        WriteNameList(buffer, ref pos, macS2C);
        WriteNameList(buffer, ref pos, compressionC2S);
        WriteNameList(buffer, ref pos, compressionS2C);
        WriteNameList(buffer, ref pos, []); // languages c2s
        WriteNameList(buffer, ref pos, []); // languages s2c
        buffer[pos++] = 0; // first_kex_packet_follows
        // reserved uint32 = 0 (already zero)
        pos += 4;

        var packet = new SshPacket(buffer, packetStart: 0, packetLength: pos);
        // Read the message type byte to advance the reader
        packet.Reader.ReadByte();
        return new KexInit(packet);
    }

    private static int GetNameListWireSize(string[] names)
    {
        if (names.Length == 0)
            return 4;
        return 4 + System.Text.Encoding.ASCII.GetByteCount(string.Join(",", names));
    }

    private static void WriteNameList(byte[] buffer, ref int pos, string[] names)
    {
        var str = string.Join(",", names);
        var bytes = System.Text.Encoding.ASCII.GetBytes(str);
        ByteWriter.WriteUint(buffer.AsSpan(pos), (uint)bytes.Length);
        pos += 4;
        Array.Copy(bytes, 0, buffer, pos, bytes.Length);
        pos += bytes.Length;
    }

    private static KexInitExchangeResult CreateResult(KexInit client, byte[] serverPayload)
    {
        var view = new Surfus.Shell.MessageViews.KeyExchange.KexInitView(serverPayload);
        var serverRawBytes = new byte[1 + view.BytesConsumed];
        serverRawBytes[0] = (byte)Messages.MessageType.SSH_MSG_KEXINIT;
        serverPayload.AsSpan(0, view.BytesConsumed).CopyTo(serverRawBytes.AsSpan(1));

        return new KexInitExchangeResult(
            client,
            serverRawBytes,
            keyExchangeAlgorithm: Negotiate(client.KexAlgorithms, view.KexAlgorithms),
            serverHostKeyAlgorithm: Negotiate(client.ServerHostKeyAlgorithms, view.ServerHostKeyAlgorithms),
            encryptionClientToServer: Negotiate(client.EncryptionClientToServer, view.EncryptionClientToServer),
            encryptionServerToClient: Negotiate(client.EncryptionServerToClient, view.EncryptionServerToClient),
            messageAuthenticationClientToServer: Negotiate(client.MacClientToServer, view.MacClientToServer),
            messageAuthenticationServerToClient: Negotiate(client.MacServerToClient, view.MacServerToClient),
            compressionClientToServer: Negotiate(client.CompressionClientToServer, view.CompressionClientToServer),
            compressionServerToClient: Negotiate(client.CompressionServerToClient, view.CompressionServerToClient)
        );
    }

    private static string Negotiate(Surfus.Shell.Extensions.NameList client, SshNameList server)
    {
        foreach (var name in client.Names)
            if (server.Contains(System.Text.Encoding.ASCII.GetBytes(name)))
                return name;
        throw new Exceptions.SshException("No common algorithm");
    }

    private static byte[] CreateServerPayload(
        string[] kex,
        string[] hostKey,
        string[] encryptionC2S,
        string[] encryptionS2C,
        string[] macC2S,
        string[] macS2C,
        string[] compressionC2S,
        string[] compressionS2C
    )
    {
        var size =
            16 // random bytes
            + GetNameListWireSize(kex)
            + GetNameListWireSize(hostKey)
            + GetNameListWireSize(encryptionC2S)
            + GetNameListWireSize(encryptionS2C)
            + GetNameListWireSize(macC2S)
            + GetNameListWireSize(macS2C)
            + GetNameListWireSize(compressionC2S)
            + GetNameListWireSize(compressionS2C)
            + GetNameListWireSize([]) // languages c2s
            + GetNameListWireSize([]) // languages s2c
            + 1 // first_kex_packet_follows
            + 4; // reserved

        var payload = new byte[size];
        var pos = 16; // skip random bytes
        WriteNameListRaw(payload, ref pos, kex);
        WriteNameListRaw(payload, ref pos, hostKey);
        WriteNameListRaw(payload, ref pos, encryptionC2S);
        WriteNameListRaw(payload, ref pos, encryptionS2C);
        WriteNameListRaw(payload, ref pos, macC2S);
        WriteNameListRaw(payload, ref pos, macS2C);
        WriteNameListRaw(payload, ref pos, compressionC2S);
        WriteNameListRaw(payload, ref pos, compressionS2C);
        WriteNameListRaw(payload, ref pos, []); // languages c2s
        WriteNameListRaw(payload, ref pos, []); // languages s2c
        payload[pos++] = 0; // first_kex_packet_follows
        pos += 4; // reserved

        return payload;
    }

    private static void WriteNameListRaw(byte[] buffer, ref int pos, string[] names)
    {
        var str = string.Join(",", names);
        var bytes = System.Text.Encoding.ASCII.GetBytes(str);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(pos), (uint)bytes.Length);
        pos += 4;
        Array.Copy(bytes, 0, buffer, pos, bytes.Length);
        pos += bytes.Length;
    }
}
