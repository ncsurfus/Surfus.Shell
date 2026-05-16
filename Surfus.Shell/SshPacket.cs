using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    /// <summary>
    /// Represents an SSH Packet.
    /// </summary>
    public class SshPacket
    {
        /// <summary>
        /// The index of the sequence number for all packets.
        /// </summary>
        internal const int SequenceIndex = 0;

        /// <summary>
        /// The index of the packet size for all packets.
        /// </summary>
        internal const int PacketSizeIndex = 4;

        /// <summary>
        /// The index of the padding byte for all packets.
        /// </summary>
        internal const int PaddingByteIndex = 8;

        /// <summary>
        /// The index of when the packet data begins for all packets.
        /// </summary>
        internal const int DataIndex = 9;

        /// <summary>
        /// A random number generator used to generate padding.
        /// </summary>
        private static readonly RandomNumberGenerator RandomGenerator = RandomNumberGenerator.Create();

        /// <summary>
        /// A ByteReader for the SSH Packet.
        /// </summary>
        internal readonly ByteReader Reader;

        /// <summary>
        /// The raw data of the entire SSH Packet.
        /// </summary>
        internal readonly byte[] Buffer;

        /// <summary>
        /// The length of the buffer.
        /// </summary>
        internal int Length;

        /// <summary>
        /// The offset of the buffer. Hardcoded to 4 to represent the space allocated for the packet sequence identifier.
        /// </summary>
        internal readonly int Offset;

        /// <summary>
        /// Constructs an SSH Packet from the compressed payload and padding multiplier. Used to write a packet.
        /// </summary>
        /// <param name="compressedPayload">The compressed payload.</param>
        /// <param name="paddingMultiplier">The padding multipler.</param>
        internal SshPacket(ByteWriter compressedPayload, int paddingMultiplier, bool isEtm = false)
        {
            // Generate padding.
            // For ETM, the encrypted portion excludes the 4-byte packet length, so alignment is on (1 + data + padding).
            // For non-ETM, alignment is on (4 + 1 + data + padding).
            var alignBase = isEtm ? (1 + compressedPayload.DataLength) : (5 + compressedPayload.DataLength);
            var paddingLength = -(alignBase % paddingMultiplier) + paddingMultiplier * 2;
            paddingLength = paddingLength <= 255 ? paddingLength : paddingLength - paddingMultiplier;
            var padding = new byte[paddingLength];
            RandomGenerator.GetBytes(padding);

            // Add 4 for the MAC authentication packet sequence number.
            // Offset everything by 4...
            Buffer = compressedPayload.Bytes;

            // Write Packet Length into 'Raw'
            var length = (uint)(compressedPayload.DataLength + padding.Length + 1);
            ByteWriter.WriteUint(Buffer.AsSpan(PacketSizeIndex), length);

            // Write Padding Length into 'Raw'
            Buffer[PaddingByteIndex] = (byte)padding.Length;

            // Write Padding into 'Raw'
            Array.Copy(padding, 0, Buffer, compressedPayload.PaddingIndex, padding.Length);

            Reader = new ByteReader(((ReadOnlyMemory<byte>)Buffer).Slice(DataIndex));

            // The Packet Sequence Identifier isn't part of the actual length.
            Offset = 4;
            Length = compressedPayload.PaddingIndex + paddingLength - 4; // Everything is valid *except* for the first 4 bytes and any unused padding.
        }

        /// <summary>
        /// Constructs an SSH Packet from the compressed payload and padding multiplier. Used to write a packet.
        /// </summary>
        /// <param name="compressedPayload">The compressed payload.</param>
        /// <param name="paddingMultiplier">The padding multipler.</param>
        internal SshPacket(byte[] compressedPayload, int paddingMultiplier)
        {
            // Generate padding
            var paddingLength = -((5 + compressedPayload.Length) % paddingMultiplier) + paddingMultiplier * 2;
            paddingLength = paddingLength <= 255 ? paddingLength : paddingLength - paddingMultiplier;
            var padding = new byte[paddingLength];
            RandomGenerator.GetBytes(padding);

            // Add 4 for the MAC authentication packet sequence number.
            // Offset everything by 4...
            Buffer = new byte[4 + 5 + compressedPayload.Length + padding.Length];

            // Write Packet Length into 'Raw'
            var length = (uint)(compressedPayload.Length + padding.Length + 1);
            ByteWriter.WriteUint(Buffer.AsSpan(4), length);

            // Write Padding Length into 'Raw'
            Buffer[8] = (byte)padding.Length;

            // Write Payload into 'Raw'
            Array.Copy(compressedPayload, 0, Buffer, 9, compressedPayload.Length);

            // Write Padding into 'Raw'
            Array.Copy(padding, 0, Buffer, 9 + compressedPayload.Length, padding.Length);

            Reader = new ByteReader(((ReadOnlyMemory<byte>)Buffer).Slice(9));

            // The Packet Sequence Identifier isn't part of the actual length.
            Offset = 4;
            Length = Buffer.Length - 4;
        }

        /// <summary>
        /// Whether this packet's buffer was rented from ArrayPool.
        /// </summary>
        private readonly bool _fromPool;

        /// <summary>
        /// Creates an outbound packet from an IClientMessage, writing directly into a pooled buffer.
        /// The caller must call Return() or dispose via the pooled buffer when done.
        /// </summary>
        internal static SshPacket Create(IClientMessage message, uint sequenceNumber, int blockSize, bool isEtm)
        {
            var payloadSize = 1 + message.GetPayloadSize(); // type byte + payload

            // Compute padding
            var alignBase = isEtm ? (1 + payloadSize) : (5 + payloadSize);
            var paddingLength = -(alignBase % blockSize) + blockSize * 2;
            paddingLength = paddingLength <= 255 ? paddingLength : paddingLength - blockSize;

            // packet_length = padding_length_byte + payload + padding
            var packetLength = 1 + payloadSize + paddingLength;
            var tagSize = 16; // max AEAD tag — caller trims if not AEAD
            var bufferSize = 4 + 4 + packetLength + tagSize;

            var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);

            // [0..4]   sequence number
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0), sequenceNumber);

            // [4..8]   packet_length
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(4), (uint)packetLength);

            // [8]      padding_length
            buffer[8] = (byte)paddingLength;
            // [9..]    message type + payload
            var writer = new SpanWriter(buffer.AsSpan(9));
            writer.WriteByte((byte)message.Type);
            message.WritePayload(ref writer);

            // padding
            RandomNumberGenerator.Fill(buffer.AsSpan(9 + payloadSize, paddingLength));

            return new SshPacket(buffer, packetStart: 4, packetLength: 4 + packetLength, pooled: true);
        }

        /// <summary>
        /// Constructs an SSH Packet from incoming data.
        /// </summary>
        internal SshPacket(byte[] buffer, int packetStart, int packetLength, bool pooled = false)
        {
            // An extra 4 bytes were allocated at the start of the packet for the HMAC.
            // First 4 bytes of buffer is the size.
            // The 5th byte (index 4) is the amount of padding.
            // The 6th byte (index 5) is the start of the payload.
            // The total size of the payload is BufferSize - 4 (Packet Length Bytes) - 1 (Padding Size Byte) - Padding Size
            Buffer = buffer;
            Reader = new ByteReader(((ReadOnlyMemory<byte>)Buffer).Slice(5 + packetStart)); // Start reading after the first 5 bytes of the packet (skipping the packet length and padding amount)
            Offset = packetStart;
            Length = packetLength;
            _fromPool = pooled;
        }

        /// <summary>
        /// The buffer if it was rented from the pool, null otherwise.
        /// Used to pass ownership to MessageEvent.
        /// </summary>
        internal byte[]? PooledBuffer => _fromPool ? Buffer : null;

        /// <summary>
        /// Returns the buffer to the pool if it was rented. Safe to call multiple times.
        /// </summary>
        private int _returned;

        /// <summary>
        /// Returns the buffer to the pool if it was rented. Safe to call multiple times.
        /// </summary>
        internal void Return()
        {
            if (_fromPool && Interlocked.CompareExchange(ref _returned, 1, 0) == 0)
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }
        }
    }
}
