using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Crypto
{
    internal class NoCrypto : CryptoAlgorithm
    {
        public override int CipherBlockSize { get; } = 8;
        public override int InitializationVectorSize { get; } = 0;
        public override int KeySize { get; } = 0;

        public override void Dispose()
        {
        }

        public override async Task<SshPacket> ReadPacketAsync(NetworkStream networkStream, CancellationToken cancellationToken)
        {
            var packetLength = await networkStream.ReadUInt32Async(cancellationToken);
            if (packetLength > 35000) throw new InvalidOperationException($"Packet length is too large {packetLength}");
            var secondBlock = await networkStream.ReadBytesAsync(packetLength, cancellationToken);

            return new SshPacket(packetLength.GetBigEndianBytes(), secondBlock);
        }

        public override byte[] Encrypt(byte[] plainText)
        {
            return plainText;
        }

        public override void Initialize(byte[] initializationVector, byte[] key)
        {
            
        }
    }
}
