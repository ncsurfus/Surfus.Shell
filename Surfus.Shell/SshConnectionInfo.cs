using System;
using Surfus.Shell.Compression;
using Surfus.Shell.Crypto;
using Surfus.Shell.MessageAuthentication;

namespace Surfus.Shell
{
    /// <summary>
    /// Connection information of the SSH session.
    /// </summary>
    public class SshConnectionInfo : IDisposable
    {
        /// <summary>
        /// The provided hostname of the server.
        /// </summary>
        public string Hostname { get; internal set; }

        /// <summary>
        /// The port that was connected to.
        /// </summary>
        public ushort Port { get; internal set; }

        /// <summary>
        /// Our SSH client version.
        /// </summary>
        public string ClientVersion { get; internal set; } = "SSH-2.0-Surfus-1.00";

        /// <summary>
        /// The SSH version sent by the server.
        /// </summary>
        public string ServerVersion { get; internal set; }

        /// <summary>
        /// The server certificate.
        /// </summary>
        public ReadOnlyMemory<byte> ServerCertificate { get; internal set; }

        /// <summary>
        /// The bit count of the certificate.
        /// </summary>
        public int ServerCertificateSize { get; internal set; }

        /// <summary>
        /// The inbound packet sequence number.
        /// </summary>
        internal uint InboundPacketSequence { get; set; }

        /// <summary>
        /// The outbound packet sequence number.
        /// </summary>
        internal uint OutboundPacketSequence { get; set; }

        /// <summary>
        /// The Key Exchanger that sets up a secure connection.
        /// </summary>
        internal SshKeyExchanger KeyExchanger { get; set; }

        /// <summary>
        /// The authentication module.
        /// </summary>
        internal SshAuthentication Authentication { get; set; }

        /// <summary>
        /// The algorithm used to compress data from the server.
        /// </summary>
        internal CompressionAlgorithm ReadCompressionAlgorithm { get; set; } = new NoCompression();

        /// <summary>
        /// The algorithm used to compress data sent to the server.
        /// </summary>
        internal CompressionAlgorithm WriteCompressionAlgorithm { get; set; } = new NoCompression();

        /// <summary>
        /// The algorithm used to encrypt data from the server.
        /// </summary>
        internal CryptoAlgorithm ReadCryptoAlgorithm { get; set; } = new NoCrypto();

        /// <summary>
        /// The algorithm used to decrypt data from the server.
        /// </summary>
        internal CryptoAlgorithm WriteCryptoAlgorithm { get; set; } = new NoCrypto();

        /// <summary>
        /// The algorithm used to validate messages from the server.
        /// </summary>
        internal MacAlgorithm ReadMacAlgorithm { get; set; } = new NoMessageAuthentication();

        /// <summary>
        /// The algorithm used to validate messages to the server.
        /// </summary>
        internal MacAlgorithm WriteMacAlgorithm { get; set; } = new NoMessageAuthentication();


        // TODO: Move all internal items into a separate class and get rid of this dispose method.
        /// <summary>
        /// Disposes the ConnectionInfo.
        /// </summary>
        public void Dispose()
        {
            ReadCompressionAlgorithm.Dispose();
            WriteCompressionAlgorithm.Dispose();
            ReadCryptoAlgorithm.Dispose();
            WriteCryptoAlgorithm.Dispose();
        }
    }
}
