using System;
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Crypto
{
    /// <summary>
    /// Implements aes128-gcm@openssh.com and aes256-gcm@openssh.com AEAD ciphers.
    /// Packet format: [4-byte unencrypted packet_length (AAD)] [encrypted body] [16-byte GCM tag]
    /// Nonce: full 12-byte IV from key derivation, incremented as a big-endian integer after each packet.
    /// </summary>
    public sealed class AesGcmCryptoAlgorithm : CryptoAlgorithm
    {
        private const int TagSize = 16;
        private const int NonceSize = 12;

        private readonly int _keyBits;
        private AesGcm _aesGcm;
        private byte[] _nonce;

        internal AesGcmCryptoAlgorithm(int keyBits)
        {
            _keyBits = keyBits;
        }

        internal override int CipherBlockSize => 16;
        internal override int InitializationVectorSize => NonceSize;
        internal override int KeySize => _keyBits / 8;
        internal override bool IsAead => true;

        internal override void Initialize(byte[] initializationVector, byte[] key)
        {
            var usableKey = key.AsSpan(0, KeySize).ToArray();
            _nonce = initializationVector.AsSpan(0, NonceSize).ToArray();
            _aesGcm = new AesGcm(usableKey, TagSize);
            CryptographicOperations.ZeroMemory(usableKey);
        }

        internal override void Encrypt(byte[] buffer, int offset, int length)
        {
            var aad = buffer.AsSpan(offset, 4);
            var plaintext = buffer.AsSpan(offset + 4, length - 4);
            var tag = buffer.AsSpan(offset + length, TagSize);

            _aesGcm.Encrypt(_nonce, plaintext, plaintext, tag, aad);
            IncrementNonce();
        }

        internal override async Task<SshPacket> ReadPacketAsync(
            NetworkStream networkStream,
            uint packetSequenceNumber,
            int hmacSize,
            CancellationToken cancellationToken
        )
        {
            var lengthBuf = new byte[4];
            await ReadExactAsync(networkStream, lengthBuf, cancellationToken).ConfigureAwait(false);

            var packetSize = (int)ByteReader.ReadUInt32(lengthBuf);
            if (packetSize > 35000)
            {
                throw new SshException("Invalid message sent, packet was too large!");
            }

            var ciphertextAndTag = new byte[packetSize + TagSize];
            await ReadExactAsync(networkStream, ciphertextAndTag, cancellationToken).ConfigureAwait(false);

            var body = ciphertextAndTag.AsSpan(0, packetSize);
            var tag = ciphertextAndTag.AsSpan(packetSize, TagSize);

            try
            {
                _aesGcm.Decrypt(_nonce, body, tag, body, lengthBuf);
            }
            catch (CryptographicException)
            {
                throw new SshException("GCM authentication failed.");
            }

            IncrementNonce();

            // Build SshPacket: [4 bytes seq_num][4 bytes packet_length][decrypted body]
            var buffer = new byte[4 + 4 + packetSize];
            ByteWriter.WriteUint(buffer.AsSpan(0), packetSequenceNumber);
            lengthBuf.CopyTo(buffer.AsSpan(4));
            body.CopyTo(buffer.AsSpan(8));

            return new SshPacket(buffer, 4, 4 + packetSize);
        }

        private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
        {
            var pos = 0;
            while (pos < buffer.Length)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(pos, buffer.Length - pos), ct).ConfigureAwait(false);
                if (n == 0)
                {
                    throw new SshException("Connection closed.");
                }
                pos += n;
            }
        }

        private void IncrementNonce()
        {
            // Increment the 12-byte nonce as a big-endian integer (last 8 bytes as counter)
            var counter = BinaryPrimitives.ReadUInt64BigEndian(_nonce.AsSpan(4));
            BinaryPrimitives.WriteUInt64BigEndian(_nonce.AsSpan(4), counter + 1);
        }

        public override void Dispose()
        {
            _aesGcm?.Dispose();
        }
    }
}
