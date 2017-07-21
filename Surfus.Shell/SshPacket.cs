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
        /// The payload of the SSH Packet.
        /// </summary>
        internal readonly ArraySegment<byte> Payload;

        /// <summary>
        /// A ByteReader for the SSH Packet.
        /// </summary>
        internal readonly ByteReader Reader;

        /// <summary>
        /// The raw data of the entire SSH Packet.
        /// </summary>
        internal readonly byte[] Raw;

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

            Raw = new byte[5 + compressedPayload.Length + padding.Length];

            // Write Packet Length into 'Raw'
            var length = (uint)(compressedPayload.Length + padding.Length + 1);
            Array.Copy(length.GetBigEndianBytes(), 0, Raw, 0, 4);

            // Write Padding Length into 'Raw'
            Raw[4] = (byte)padding.Length;

            // Write Payload into 'Raw'
            Array.Copy(compressedPayload, 0, Raw, 5, compressedPayload.Length);

            // Write Padding into 'Raw'
            Array.Copy(padding, 0, Raw, 5 + compressedPayload.Length, padding.Length);

            Payload = new ArraySegment<byte>(Raw, 5, Raw.Length - 5 - Raw[4]);
            Reader = new ByteReader(Raw, 5);
        }

        /// <summary>
        /// Constructs an SSH Packet from incoming data.
        /// </summary>
        /// <param name="firstBlock"></param>
        /// <param name="secondBlock"></param>
        internal SshPacket(byte[] firstBlock, byte[] secondBlock)
        {
            // First 4 bytes of buffer is the size.
            // The 5th byte (index 4) is the amount of padding.
            // The 6th byte (index 5) is the start of the payload.
            // The total size of the payload is BufferSize - 4 (Packet Length Bytes) - 1 (Padding Size Byte) - Padding Size
            Raw = new byte[firstBlock.Length + secondBlock.Length];
            Array.Copy(firstBlock, 0, Raw, 0, firstBlock.Length);
            Array.Copy(secondBlock, 0, Raw, firstBlock.Length, secondBlock.Length);
            Reader = new ByteReader(Raw, 5);
            Payload = new ArraySegment<byte>(Raw, 5, Raw.Length - 5 - Raw[4]);
        }

        /// <summary>
        /// Constructs an SSH Packet from incoming data.
        /// </summary>
        /// <param name="buffer"></param>
        internal SshPacket(byte[] buffer)
        {
            // First 4 bytes of buffer is the size.
            // The 5th byte (index 4) is the amount of padding.
            // The 6th byte (index 5) is the start of the payload.
            // The total size of the payload is BufferSize - 4 (Packet Length Bytes) - 1 (Padding Size Byte) - Padding Size
            Raw = buffer;
            Reader = new ByteReader(Raw, 5);
            Payload = new ArraySegment<byte>(Raw, 5, Raw.Length - 5 - Raw[4]);
        }
    }
}
