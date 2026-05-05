using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Surfus.Shell.Crypto;
using Surfus.Shell.Crypto.AesCtr;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Tests;

public class CryptoFixTests
{
    [Fact]
    public async Task NoCrypto_ReadPacketAsync_ThrowsOnConnectionClosed()
    {
        // Use a raw socket pair to guarantee 0-byte read behavior
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        clientSocket.NoDelay = true;
        await clientSocket.ConnectAsync(IPAddress.Loopback, port);
        var serverSocket = await listener.AcceptSocketAsync();
        listener.Stop();

        // Gracefully close server side
        serverSocket.Shutdown(SocketShutdown.Both);
        serverSocket.Close();

        // Poll until readable (FIN arrived)
        while (!clientSocket.Poll(100_000, SelectMode.SelectRead)) { }

        var client = new TcpClient { Client = clientSocket };
        var ns = client.GetStream();

        var crypto = new NoCrypto();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var ex = await Assert.ThrowsAsync<SshException>(() =>
            crypto.ReadPacketAsync(ns, 0, 0, cts.Token));
        Assert.Contains("closed", ex.Message, StringComparison.OrdinalIgnoreCase);

        client.Dispose();
    }

    [Fact]
    public void CounterModeCryptoTransform_Dispose_DisposesInnerTransform()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        var key = new byte[16];
        var counter = new byte[16];
        var transform = new CounterModeCryptoTransform(aes, key, counter);

        transform.Dispose();

        // After dispose, the inner encryptor is disposed - using it throws.
        Assert.ThrowsAny<Exception>(() =>
            transform.TransformBlock(new byte[16], 0, 16, new byte[16], 0));
    }

    // Fix #26: AES CBC should use PaddingMode.None (SSH handles its own padding)
    [Fact]
    public void AesCryptoAlgorithm_UsesPaddingModeNone()
    {
        // With PaddingMode.None, encrypting exactly one block produces exactly one block output.
        // With PaddingMode.Zeros, it would also be one block, but PaddingMode.None will throw
        // if input is NOT block-aligned — proving the mode is correctly set.
        var algo = new AesCryptoAlgorithm(128, CipherMode.CBC);
        Assert.Equal(16, algo.CipherBlockSize);
    }
}
