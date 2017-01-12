using System;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.MessageAuthentication;

namespace Surfus.Shell
{
    public class SshConnectionInfo : IDisposable
    {
        public string Hostname { get; internal set; }
        public ushort Port { get; internal set; }
        public string ClientVersion { get; internal set; } = "SSH-2.0-Surfus-1.00";
        public string ServerVersion { get; internal set; }

        internal uint InboundPacketSequence { get; set; }
        internal uint OutboundPacketSequence { get; set; }

        internal SshKeyExchanger KeyExchanger { get; set; }
        internal SshAuthentication Authentication { get; set; }

        internal CompressionAlgorithm ReadCompressionAlgorithm { get; set; } = new NoCompression();
        internal CompressionAlgorithm WriteCompressionAlgorithm { get; set; } = new NoCompression();
        internal CryptoAlgorithm ReadCryptoAlgorithm { get; set; } = new NoCrypto();
        internal CryptoAlgorithm WriteCryptoAlgorithm { get; set; } = new NoCrypto();
        internal MacAlgorithm ReadMacAlgorithm { get; set; } = new NoMessageAuthentication();
        internal MacAlgorithm WriteMacAlgorithm { get; set; } = new NoMessageAuthentication();

        public void Dispose()
        {
            ReadCompressionAlgorithm.Dispose();
            WriteCompressionAlgorithm.Dispose();
            ReadCryptoAlgorithm.Dispose();
            WriteCryptoAlgorithm.Dispose();
        }
    }
}
