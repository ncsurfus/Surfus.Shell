using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
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
        private AesGcm? _aesGcm;
        private byte[]? _nonce;

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

            _aesGcm!.Encrypt(_nonce, plaintext, plaintext, tag, aad);
            IncrementNonce();
        }

        internal override void Decrypt(byte[] cipherText, int offset, int length)
        {
            // GCM decryption is handled in ReadPacketAsync. This should not be called.
            throw new NotSupportedException("GCM decryption is handled internally.");
        }

        internal override async Task<SshPacket> ReadPacketAsync(
            Stream stream,
            uint packetSequenceNumber,
            int hmacSize,
            bool isEtm,
            CancellationToken cancellationToken
        )
        {
            var lengthBuf = ArrayPool<byte>.Shared.Rent(4);
            int packetSize;
            try
            {
                await ReadExactAsync(stream, lengthBuf, 4, cancellationToken).ConfigureAwait(false);
                packetSize = (int)ByteReader.ReadUInt32(lengthBuf.AsSpan(0));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(lengthBuf);
            }

            if (packetSize > 35000)
            {
                throw new SshException("Invalid message sent, packet was too large!");
            }

            var ciphertextAndTag = ArrayPool<byte>.Shared.Rent(packetSize + TagSize);
            try
            {
                await ReadExactAsync(stream, ciphertextAndTag, packetSize + TagSize, cancellationToken).ConfigureAwait(false);

                var body = ciphertextAndTag.AsSpan(0, packetSize);
                var tag = ciphertextAndTag.AsSpan(packetSize, TagSize);

                // Need the length bytes for AAD
                var aad = new byte[4];
                ByteWriter.WriteUint(aad.AsSpan(0), (uint)packetSize);

                try
                {
                    _aesGcm!.Decrypt(_nonce, body, tag, body, aad);
                }
                catch (CryptographicException)
                {
                    throw new SshException("GCM authentication failed.");
                }

                IncrementNonce();

                // Build SshPacket: [4 bytes seq_num][4 bytes packet_length][decrypted body]
                var buffer = ArrayPool<byte>.Shared.Rent(4 + 4 + packetSize);
                ByteWriter.WriteUint(buffer.AsSpan(0), packetSequenceNumber);
                ByteWriter.WriteUint(buffer.AsSpan(4), (uint)packetSize);
                body.CopyTo(buffer.AsSpan(8));

                return new SshPacket(buffer, 4, 4 + packetSize, pooled: true);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(ciphertextAndTag);
            }
        }

        private static async Task ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken ct)
        {
            var pos = 0;
            while (pos < count)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(pos, count - pos), ct).ConfigureAwait(false);
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
            var counter = BinaryPrimitives.ReadUInt64BigEndian(_nonce!.AsSpan(4));
            BinaryPrimitives.WriteUInt64BigEndian(_nonce.AsSpan(4), counter + 1);
        }

        public override void Dispose()
        {
            _aesGcm?.Dispose();
        }
    }
}
