using System;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;

namespace Surfus.Shell
{
    /// <summary>
    /// Represents an SSH Packet.
    /// </summary>
    public class SshPacket
    {
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
        internal readonly int Offset = 4;

        /// <summary>
        /// Constructs an SSH Packet from the compressed payload and padding multiplier. Used to write a packet.
        /// </summary>
        /// <param name="compressedPayload">The compressed payload.</param>
        /// <param name="paddingMultiplier">The padding multipler.</param>
        internal SshPacket(byte[] compressedPayload, int paddingMultiplier)
        {
            // Generate padding
            var paddingLength = -((5 + compressedPayload.Length) % paddingMultiplier) + paddingMultiplier * 2;
            var padding = new byte[paddingLength <= 255 ? paddingLength : paddingLength - paddingMultiplier];
            RandomGenerator.GetBytes(padding);

            if (padding.Length > byte.MaxValue) throw new ArgumentException($"{nameof(padding)} cannot be greater than {byte.MaxValue}");

            // Add 4 for the MAC authentication packet sequence number.
            // Offset everything by 4...
            Buffer = new byte[4 + 5 + compressedPayload.Length + padding.Length];

            // Write Packet Length into 'Raw'
            var length = (uint)(compressedPayload.Length + padding.Length + 1);
            Array.Copy(length.GetBigEndianBytes(), 0, Buffer, 4, 4);

            // Write Padding Length into 'Raw'
            Buffer[8] = (byte)padding.Length;

            // Write Payload into 'Raw'
            Array.Copy(compressedPayload, 0, Buffer, 9, compressedPayload.Length);

            // Write Padding into 'Raw'
            Array.Copy(padding, 0, Buffer, 9 + compressedPayload.Length, padding.Length);

            Reader = new ByteReader(Buffer, 9);

            // The Packet Sequence Identifier isn't part of the actual length.
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
            Reader = new ByteReader(Buffer, 5 + packetStart); // Start reading after the first 5 bytes of the packet (skipping the packet length and padding amount)
            Length = packetLength;
        }
    }
}
