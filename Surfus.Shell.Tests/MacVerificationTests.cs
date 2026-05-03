using Surfus.Shell.MessageAuthentication;

namespace Surfus.Shell.Tests;

public class MacVerificationTests
{
    private static SshPacket CreatePacketWithMac(MacAlgorithm mac, byte[] key)
    {
        mac.Initialize(key);

        // Build a minimal packet: 4 bytes seq + payload
        var payload = new byte[] { 0x01, 0x02, 0x03 };
        var packet = new SshPacket(payload, 8);

        // Compute MAC and append it to the buffer
        var computedMac = mac.ComputeHash(0, packet);
        var bufferWithMac = new byte[packet.Buffer.Length + computedMac.Length];
        Array.Copy(packet.Buffer, bufferWithMac, packet.Buffer.Length);
        Array.Copy(computedMac, 0, bufferWithMac, packet.Length + 4, computedMac.Length);

        return new SshPacket(bufferWithMac, packet.Offset, packet.Length);
    }

    [Theory]
    [InlineData(typeof(HmacSha256MacAlgorithm))]
    [InlineData(typeof(HmacSha512MacAlgorithm))]
    [InlineData(typeof(HmacSha1MacAlgorithm))]
    [InlineData(typeof(HmacSha1B96MacAlgorithm))]
    public void VerifyMac_ValidMac_ReturnsTrue(Type macType)
    {
        var mac = (MacAlgorithm)Activator.CreateInstance(macType)!;
        var key = new byte[mac.KeySize];
        Array.Fill(key, (byte)0xAB);

        var packet = CreatePacketWithMac(mac, key);
        Assert.True(mac.VerifyMac(0, packet));
    }

    [Theory]
    [InlineData(typeof(HmacSha256MacAlgorithm))]
    [InlineData(typeof(HmacSha512MacAlgorithm))]
    [InlineData(typeof(HmacSha1MacAlgorithm))]
    [InlineData(typeof(HmacSha1B96MacAlgorithm))]
    public void VerifyMac_CorruptedMac_ReturnsFalse(Type macType)
    {
        var mac = (MacAlgorithm)Activator.CreateInstance(macType)!;
        var key = new byte[mac.KeySize];
        Array.Fill(key, (byte)0xAB);

        var packet = CreatePacketWithMac(mac, key);

        // Corrupt the last byte of the MAC
        packet.Buffer[packet.Length + 4 + mac.OutputSize - 1] ^= 0xFF;
        Assert.False(mac.VerifyMac(0, packet));
    }

    [Theory]
    [InlineData(typeof(HmacSha256MacAlgorithm))]
    [InlineData(typeof(HmacSha512MacAlgorithm))]
    [InlineData(typeof(HmacSha1MacAlgorithm))]
    [InlineData(typeof(HmacSha1B96MacAlgorithm))]
    public void VerifyMac_CorruptedFirstByte_ReturnsFalse(Type macType)
    {
        var mac = (MacAlgorithm)Activator.CreateInstance(macType)!;
        var key = new byte[mac.KeySize];
        Array.Fill(key, (byte)0xAB);

        var packet = CreatePacketWithMac(mac, key);

        // Corrupt the first byte of the MAC
        packet.Buffer[packet.Length + 4] ^= 0xFF;
        Assert.False(mac.VerifyMac(0, packet));
    }
}
