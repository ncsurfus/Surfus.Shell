using System;
using System.Security.Cryptography;

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
        /// Constructs an SSH Packet from incoming data.
        /// </summary>
        /// <param name="buffer"></param>
        internal SshPacket(byte[] buffer, int packetStart, int packetLength)
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
        }
    }
}
