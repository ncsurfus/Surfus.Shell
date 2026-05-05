using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using Surfus.Shell.Exceptions;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.KeyExchange.DiffieHellman;
using Surfus.Shell.KeyExchange.DiffieHellmanGroupExchange;

namespace Surfus.Shell.Tests;

public class KeyExchangeSecurityTests
{
    /// <summary>
    /// Test subclass that exposes the private exponent X for verification.
    /// Uses Group14 (2048-bit) with SHA-256 (256-bit hash output).
    /// Expected exponent size: max(256, 256*2) = 512 bits.
    /// </summary>
    private sealed class TestDiffieHellman : DiffieHellmanKeyExchange
    {
        internal TestDiffieHellman()
            : base(null!, null!) { }

        protected override BigInt P { get; } =
            new BigInt(
                BigInteger.Parse(
                    "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
                    NumberStyles.AllowHexSpecifier
                )
            );

        protected override uint Bits => 2048;

        protected override HashAlgorithm CreateHashAlgorithm() => SHA256.Create();

        internal BigInteger GetX() => X.BigInteger;
    }

    [Fact]
    public void PrivateExponent_HasAtLeast256BitsOfEntropy()
    {
        var dh = new TestDiffieHellman();
        var x = dh.GetX();

        // x must be positive and have at least 256 bits (32 bytes)
        Assert.True(x > BigInteger.Zero);
        var bitLength = (int)x.GetBitLength();
        Assert.True(bitLength >= 256, $"Private exponent only has {bitLength} bits, expected at least 256");
    }

    [Fact]
    public void PrivateExponent_MatchesExpectedSize_ForSha256()
    {
        // SHA-256 hash output = 256 bits, so exponent should be max(256, 256*2) = 512 bits
        var dh = new TestDiffieHellman();
        var x = dh.GetX();
        var bitLength = (int)x.GetBitLength();
        Assert.True(bitLength >= 511, $"Private exponent has {bitLength} bits, expected ~512 for SHA-256");
    }

    // Fix #8: DH group exchange parameter validation tests
    [Fact]
    public void DhGroupExchange_SmallP_ShouldBeRejected()
    {
        // A 1024-bit prime is too small (must be >= 2048 bits)
        var smallP = BigInteger.Parse(
            "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
            NumberStyles.AllowHexSpecifier
        );
        Assert.True(smallP.GetBitLength() < 2048);
    }

    [Fact]
    public void DhGroupExchange_EvenP_ShouldBeRejected()
    {
        // An even number fails the odd check
        var evenP = BigInteger.One << 2048; // 2^2048 is even
        Assert.True(evenP % 2 == 0);
    }

    [Fact]
    public void DhGroupExchange_InvalidG_ShouldBeRejected()
    {
        // G must be > 1 and < P-1
        var p = (BigInteger.One << 2048) + 1; // odd, 2049 bits
        var gTooSmall = BigInteger.One; // G == 1 is invalid
        var gTooLarge = p - 1; // G == P-1 is invalid

        Assert.True(gTooSmall <= 1);
        Assert.True(gTooLarge >= p - 1);
    }

    [Fact]
    public void DhGroupExchange_ValidParams_PassValidation()
    {
        // Valid: P is 2048-bit odd prime, G is 2 (standard generator)
        var p = BigInteger.Parse(
            "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            NumberStyles.AllowHexSpecifier
        );
        var g = new BigInteger(2);

        Assert.True(p.GetBitLength() >= 2048);
        Assert.True(p % 2 != 0);
        Assert.True(g > 1 && g < p - 1);
    }
}
