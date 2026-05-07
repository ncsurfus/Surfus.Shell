using System.Security.Cryptography;
using Surfus.Shell.Authentication;

namespace Surfus.Shell.Tests;

public class PrivateKeyAuthTests
{
    private const string User = "testuser";

    private static CancellationToken Timeout(int seconds = 10) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static (string privateKeyPem, string publicKeyPath) GenerateRsaTestKey()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportRSAPrivateKeyPem();
        var pubKeyPath = Path.GetTempFileName();
        var pubParams = rsa.ExportParameters(false);
        // Write OpenSSH authorized_keys format
        var blob = BuildSshRsaBlob(pubParams);
        File.WriteAllText(pubKeyPath, $"ssh-rsa {Convert.ToBase64String(blob)} test@test");
        return (pem, pubKeyPath);
    }

    private static (string privateKeyPem, string publicKeyPath) GenerateEcdsaTestKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = ecdsa.ExportECPrivateKeyPem();
        var pubKeyPath = Path.GetTempFileName();
        var pubParams = ecdsa.ExportParameters(false);
        var blob = BuildSshEcdsaBlob(pubParams, "nistp256");
        File.WriteAllText(pubKeyPath, $"ecdsa-sha2-nistp256 {Convert.ToBase64String(blob)} test@test");
        return (pem, pubKeyPath);
    }

    [Fact]
    public async Task RsaKey_Authenticates()
    {
        var (pem, pubKeyPath) = GenerateRsaTestKey();
        try
        {
            await using var server = await SshTestServer.StartAsync(authorizedKeyPath: pubKeyPath);
            await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
            await client.ConnectAsync(Timeout());
            await client.AuthenticateAsync(User, new PrivateKeyAuth(pem), Timeout());
            Assert.True(client.IsConnected);
        }
        finally
        {
            File.Delete(pubKeyPath);
        }
    }

    [Fact]
    public async Task EcdsaKey_Authenticates()
    {
        var (pem, pubKeyPath) = GenerateEcdsaTestKey();
        try
        {
            await using var server = await SshTestServer.StartAsync(authorizedKeyPath: pubKeyPath);
            await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
            await client.ConnectAsync(Timeout());
            await client.AuthenticateAsync(User, new PrivateKeyAuth(pem), Timeout());
            Assert.True(client.IsConnected);
        }
        finally
        {
            File.Delete(pubKeyPath);
        }
    }

    [Fact]
    public async Task WrongKey_Throws()
    {
        // Generate one key for the server, authenticate with a different one
        var (_, pubKeyPath) = GenerateRsaTestKey();
        using var wrongRsa = RSA.Create(2048);
        var wrongPem = wrongRsa.ExportRSAPrivateKeyPem();
        try
        {
            await using var server = await SshTestServer.StartAsync(authorizedKeyPath: pubKeyPath);
            await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
            await client.ConnectAsync(Timeout());
            await Assert.ThrowsAsync<Exceptions.SshInvalidCredentials>(
                () => client.AuthenticateAsync(User, new PrivateKeyAuth(wrongPem), Timeout())
            );
        }
        finally
        {
            File.Delete(pubKeyPath);
        }
    }

    [Fact]
    public async Task PreLoadedKey_Authenticates()
    {
        var rsa = RSA.Create(2048);
        var pubParams = rsa.ExportParameters(false);
        var blob = BuildSshRsaBlob(pubParams);
        var pubKeyPath = Path.GetTempFileName();
        File.WriteAllText(pubKeyPath, $"ssh-rsa {Convert.ToBase64String(blob)} test@test");
        try
        {
            await using var server = await SshTestServer.StartAsync(authorizedKeyPath: pubKeyPath);
            await using var client = new SshClient("127.0.0.1", (ushort)server.Port);
            await client.ConnectAsync(Timeout());
            await client.AuthenticateAsync(User, new PrivateKeyAuth(rsa), Timeout());
            Assert.True(client.IsConnected);
        }
        finally
        {
            File.Delete(pubKeyPath);
        }
    }

    [Fact]
    public void LoadKey_InvalidPem_Throws()
    {
        Assert.Throws<NotSupportedException>(() => new PrivateKeyAuth("not a valid pem"));
    }

    // --- Helpers to build SSH public key blobs ---

    private static byte[] BuildSshRsaBlob(RSAParameters p)
    {
        using var ms = new MemoryStream();
        WriteSshString(ms, "ssh-rsa");
        WriteSshMpint(ms, p.Exponent!);
        WriteSshMpint(ms, p.Modulus!);
        return ms.ToArray();
    }

    private static byte[] BuildSshEcdsaBlob(ECParameters p, string curveName)
    {
        var keyType = $"ecdsa-sha2-{curveName}";
        var q = new byte[1 + p.Q.X.Length + p.Q.Y.Length];
        q[0] = 0x04;
        p.Q.X.CopyTo(q, 1);
        p.Q.Y.CopyTo(q, 1 + p.Q.X.Length);

        using var ms = new MemoryStream();
        WriteSshString(ms, keyType);
        WriteSshString(ms, curveName);
        WriteSshBytes(ms, q);
        return ms.ToArray();
    }

    private static void WriteSshString(MemoryStream ms, string s)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(s);
        WriteSshBytes(ms, bytes);
    }

    private static void WriteSshBytes(MemoryStream ms, byte[] data)
    {
        var len = BitConverter.GetBytes((uint)data.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(len);
        ms.Write(len);
        ms.Write(data);
    }

    private static void WriteSshMpint(MemoryStream ms, byte[] data)
    {
        if (data.Length > 0 && (data[0] & 0x80) != 0)
        {
            var len = BitConverter.GetBytes((uint)(data.Length + 1));
            if (BitConverter.IsLittleEndian) Array.Reverse(len);
            ms.Write(len);
            ms.WriteByte(0);
            ms.Write(data);
        }
        else
        {
            WriteSshBytes(ms, data);
        }
    }
}
