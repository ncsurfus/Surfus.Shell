using System;
using System.Security.Cryptography;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.KeyExchange;
using Surfus.Shell.KeyExchange.DiffieHellman;
using Surfus.Shell.KeyExchange.DiffieHellmanGroupExchange;
using Surfus.Shell.MessageAuthentication;
using Surfus.Shell.Signing;

namespace Surfus.Shell
{
    /// <summary>
    /// Describes an SSH algorithm by its wire name and a factory to create instances.
    /// </summary>
    public record AlgorithmDescriptor<T>
    {
        /// <summary>
        /// The SSH wire name (e.g., "aes256-ctr").
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Factory to create a new instance of this algorithm.
        /// </summary>
        internal Func<T> Factory { get; }

        public AlgorithmDescriptor(string name, Func<T> factory)
        {
            Name = name;
            Factory = factory;
        }

        public T Create() => Factory();

        public override string ToString() => Name;
    }

    /// <summary>
    /// Describes a host key algorithm that requires the server's public key to construct.
    /// </summary>
    public record SignerDescriptor
    {
        public string Name { get; }
        internal Func<ReadOnlyMemory<byte>, Signer> Factory { get; }

        public SignerDescriptor(string name, Func<ReadOnlyMemory<byte>, Signer> factory)
        {
            Name = name;
            Factory = factory;
        }

        public override string ToString() => Name;
    }

    /// <summary>
    /// Describes a key exchange algorithm that requires context to construct.
    /// </summary>
    public record KeyExchangeDescriptor
    {
        public string Name { get; }
        internal Func<KexContext, KexInitExchangeResult, KeyExchangeAlgorithm> Factory { get; }

        public KeyExchangeDescriptor(string name, Func<KexContext, KexInitExchangeResult, KeyExchangeAlgorithm> factory)
        {
            Name = name;
            Factory = factory;
        }

        public override string ToString() => Name;
    }

    /// <summary>
    /// Configures which SSH algorithms are offered during key exchange.
    /// Algorithms are listed in preference order.
    /// </summary>
    public record SshAlgorithms
    {
        public AlgorithmDescriptor<CryptoAlgorithm>[] Encryption { get; init; } = DefaultEncryption;
        public AlgorithmDescriptor<MacAlgorithm>[] Mac { get; init; } = DefaultMac;
        public AlgorithmDescriptor<CompressionAlgorithm>[] Compression { get; init; } = DefaultCompression;
        public SignerDescriptor[] HostKey { get; init; } = DefaultHostKey;
        public KeyExchangeDescriptor[] KeyExchange { get; init; } = DefaultKeyExchange;

        internal string[] EncryptionNames => Array.ConvertAll(Encryption, a => a.Name);
        internal string[] MacNames => Array.ConvertAll(Mac, a => a.Name);
        internal string[] CompressionNames => Array.ConvertAll(Compression, a => a.Name);
        internal string[] HostKeyNames => Array.ConvertAll(HostKey, a => a.Name);
        internal string[] KeyExchangeNames => Array.ConvertAll(KeyExchange, a => a.Name);

        internal CryptoAlgorithm CreateEncryption(string name) => Find(Encryption, name).Create();

        internal MacAlgorithm CreateMac(string name) => Find(Mac, name).Create();

        internal CompressionAlgorithm CreateCompression(string name) => Find(Compression, name).Create();

        internal Signer CreateSigner(string name, ReadOnlyMemory<byte> serverHostKey) =>
            FindDescriptor(HostKey, name).Factory(serverHostKey);

        internal KeyExchangeAlgorithm CreateKeyExchange(string name, KexContext ctx, KexInitExchangeResult kex) =>
            FindDescriptor(KeyExchange, name).Factory(ctx, kex);

        private static AlgorithmDescriptor<T> Find<T>(AlgorithmDescriptor<T>[] descriptors, string name)
        {
            foreach (var d in descriptors)
                if (d.Name == name)
                    return d;
            throw new Exceptions.SshException($"Algorithm '{name}' is not configured.");
        }

        private static T FindDescriptor<T>(T[] descriptors, string name)
            where T : class
        {
            foreach (var d in descriptors)
                if (d.ToString() == name)
                    return d;
            throw new Exceptions.SshException($"Algorithm '{name}' is not configured.");
        }

        // --- Defaults ---

        public static readonly AlgorithmDescriptor<CryptoAlgorithm>[] DefaultEncryption = new[]
        {
            new AlgorithmDescriptor<CryptoAlgorithm>("aes256-ctr", () => new AesCtrCryptoAlgorithm(256)),
            new AlgorithmDescriptor<CryptoAlgorithm>("aes192-ctr", () => new AesCtrCryptoAlgorithm(192)),
            new AlgorithmDescriptor<CryptoAlgorithm>("aes128-ctr", () => new AesCtrCryptoAlgorithm(128)),
            new AlgorithmDescriptor<CryptoAlgorithm>("aes256-cbc", () => new AesCryptoAlgorithm(256, CipherMode.CBC)),
            new AlgorithmDescriptor<CryptoAlgorithm>("aes192-cbc", () => new AesCryptoAlgorithm(192, CipherMode.CBC)),
            new AlgorithmDescriptor<CryptoAlgorithm>("aes128-cbc", () => new AesCryptoAlgorithm(128, CipherMode.CBC)),
            new AlgorithmDescriptor<CryptoAlgorithm>("3des-cbc", () => new TripleDesCryptoAlgorithm()),
        };

        public static readonly AlgorithmDescriptor<MacAlgorithm>[] DefaultMac = new[]
        {
            new AlgorithmDescriptor<MacAlgorithm>("hmac-sha2-512", () => new HmacSha512MacAlgorithm()),
            new AlgorithmDescriptor<MacAlgorithm>("hmac-sha2-256", () => new HmacSha256MacAlgorithm()),
            new AlgorithmDescriptor<MacAlgorithm>("hmac-sha1-96", () => new HmacSha1B96MacAlgorithm()),
            new AlgorithmDescriptor<MacAlgorithm>("hmac-sha1", () => new HmacSha1MacAlgorithm()),
        };

        public static readonly AlgorithmDescriptor<CompressionAlgorithm>[] DefaultCompression = new[]
        {
            new AlgorithmDescriptor<CompressionAlgorithm>("none", () => new NoCompression()),
        };

        public static readonly SignerDescriptor[] DefaultHostKey = new[]
        {
            new SignerDescriptor("rsa-sha2-512", key => new RsaSha512(key)),
            new SignerDescriptor("rsa-sha2-256", key => new RsaSha256(key)),
            new SignerDescriptor("ecdsa-sha2-nistp256", key => new ECDsaSha2Nistp256(key)),
            new SignerDescriptor("ecdsa-sha2-nistp384", key => new ECDsaSha2Nistp384(key)),
            new SignerDescriptor("ecdsa-sha2-nistp521", key => new ECDsaSha2Nistp521(key)),
            new SignerDescriptor("ssh-rsa", key => new SshRsa(key)),
        };

        public static readonly KeyExchangeDescriptor[] DefaultKeyExchange = new[]
        {
            new KeyExchangeDescriptor(
                "diffie-hellman-group-exchange-sha256",
                (ctx, kex) => new DiffieHellmanGroupKeyExchange(ctx, kex, "SHA256")
            ),
            new KeyExchangeDescriptor("diffie-hellman-group14-sha256", (ctx, kex) => new DiffieHellmanGroup14Sha256(ctx, kex)),
            new KeyExchangeDescriptor("diffie-hellman-group16-sha512", (ctx, kex) => new DiffieHellmanGroup16Sha512(ctx, kex)),
            new KeyExchangeDescriptor("diffie-hellman-group18-sha512", (ctx, kex) => new DiffieHellmanGroup18Sha512(ctx, kex)),
            new KeyExchangeDescriptor(
                "diffie-hellman-group-exchange-sha1",
                (ctx, kex) => new DiffieHellmanGroupKeyExchange(ctx, kex, "SHA1")
            ),
            new KeyExchangeDescriptor("diffie-hellman-group14-sha1", (ctx, kex) => new DiffieHellmanGroup14Sha1(ctx, kex)),
        };
    }
}
