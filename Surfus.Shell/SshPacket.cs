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
        /// The range of bytes in the SshPacket that make up the packet payload.
        /// </summary>
        internal ArraySegment<byte> Payload { get; }

        /// <summary>
        /// The range of bytes in the SshPacket that make up the actual packet.
        /// When writing this does not include our message authentication code.
        /// When reading this does include the server's Message authentication code.
        /// </summary>
        internal ArraySegment<byte> Packet { get; }

        /// <summary>
        /// The range of bytes in the SshPacket that should be used to calculate the message authentication code.
        /// </summary>
        internal ArraySegment<byte> MacVerificationBytes { get; }

        /// <summary>
        /// The server's message authentication code.
        /// This 
        /// </summary>
        internal ArraySegment<byte> ServerMacResult { get; }

        /// <summary>
        /// Constructs an SSH Packet from the compressed payload and padding multiplier. Used to write a packet.
        /// </summary>
        /// <param name="compressedPayload">The compressed payload.</param>
        /// <param name="blockSize">The block used used to determine the padding. Must be at least 8.</param>
        internal SshPacket(ByteWriter payload, int blockSize, uint sequenceNumber)
        {
            // Generate padding to make the packet perfectly divisiblie by the block size.
            // uint (length) + byte (padding length) + payload + padding % blockSize = 0.
            var padding = new byte[(2 * blockSize) - ((5 + payload.DataLength) % blockSize)];
            RandomGenerator.GetBytes(padding); // TODO: On switch to .NET Standard 2.0, we can write directly to the buffer.

            // Add 4 for the MAC authentication packet sequence number.
            // Offset everything by 4...
            Buffer = payload.Bytes;

            // Write packet length
            var length = (uint)(payload.DataLength + padding.Length + 1);
            ByteWriter.WriteUint(Buffer, PacketSizeIndex, length);

            // Write sequence number
            ByteWriter.WriteUint(Buffer, SequenceIndex, sequenceNumber);

            // Write Padding Length into 'Raw'
            Buffer[PaddingByteIndex] = (byte)padding.Length;

            // Write Padding into 'Raw'
            Array.Copy(padding, 0, Buffer, payload.PaddingIndex, padding.Length);

            // Payload offset skips (uint)sequence + (uint)size + (byte)padding length.
            // Payload length is the size of the compressedPayload.
            Payload = new ArraySegment<byte>(Buffer, 4 + 4 + 1, payload.DataLength);

            // Packet offset skips (uint)sequence
            // Packet length is the (uint)size + (byte)padding length + (byte[])payload + (byte[])padding. 
            Packet = new ArraySegment<byte>(Buffer, 4, 4 + 1 + payload.DataLength + padding.Length);

            // MacVerificatonBytes offset skips nothing.
            // MacVerificatonBytes length is the (uint) sequence + (uint)size + (byte)padding length + (byte[])payload + (byte[])padding. 
            MacVerificationBytes = new ArraySegment<byte>(Buffer, 0, 4 + 4 + 1 + payload.DataLength + padding.Length);

            // There is no server Mac result. This is a client packet, and the computation always produces a new array, so it doesn't make sense to copy it here.

            // This packet wont be read, but for consistency the read will be set to the payload offset.
            Reader = new ByteReader(Buffer, Payload.Offset);
        }

        /// <summary>
        /// Constructs an SSH Packet from incoming data.
        /// </summary>
        /// <param name="buffer"></param>
        internal SshPacket(byte[] buffer, int packetLength, int hmacSize)
        {
            // The full buffer length is packetLength + hmacSize. The actual length property on the buffer may be larger!
            // 
            // This packet was read from the server. Description of this is below.
            // 4 bytes (uint) is the inbound packet number. This wasn't sent by the server, but we use it to calculate the message authentication code.
            // 4 bytes (uint) is the packet size, sent by the server.
            // 1 byte (byte) is the amount of padding.
            // n bytes where n = (packet size, defined above) is size of the payload and padding.
            // n bytes where n = (hmacSize) is the server's calculated message authentication code.
            // packetLength is the size of everything except the hmac.

            Buffer = buffer;
            Reader = new ByteReader(Buffer, 9); // Start reading after the first 5 bytes of the packet (skipping the packet length and padding amount)

            // Payload offset skips (uint)sequence + (uint)size + (byte)padding length.
            // Payload length = packet length - (uint)sequence + (uint)size + (byte)padding length.
            Payload = new ArraySegment<byte>(Buffer, 4 + 4 + 1, packetLength - 4 - 4 - 1);

            // Packet offset skips (uint)sequence
            // Packet length = packet length - (uint)sequence.
            Packet = new ArraySegment<byte>(Buffer, 4, packetLength - 4);

            // MacVerificatonBytes offset skips nothing.
            // MacVerificatonBytes length = packet length.
            MacVerificationBytes = new ArraySegment<byte>(Buffer, 0, packetLength);

            // Server MAC result skips the entire packet as the mac is at the end.
            ServerMacResult = new ArraySegment<byte>(Buffer, packetLength, hmacSize);
        }
    }
}
