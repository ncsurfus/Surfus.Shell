using Surfus.Shell.Common;
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
        internal readonly ByteReader PayloadReader;

        /// <summary>
        /// The raw data of the entire SSH Packet.
        /// </summary>
        private readonly byte[] _buffer;

        /// <summary>
        /// The range of bytes in the SshPacket that make up the packet payload.
        /// </summary>
        internal PacketSegment Payload { get; }

        /// <summary>
        /// The range of bytes in the SshPacket that make up the actual packet.
        /// When writing this does not include our message authentication code.
        /// When reading this does include the server's Message authentication code.
        /// </summary>
        internal PacketSegment Packet { get; }

        /// <summary>
        /// The range of bytes in the SshPacket that should be used to calculate the message authentication code.
        /// </summary>
        internal PacketSegment MacVerificationBytes { get; }

        /// <summary>
        /// The server's message authentication code.
        /// This 
        /// </summary>
        internal PacketSegment ServerMacResult { get; }

        /// <summary>
        /// Constructs an SSH Packet from the compressed payload and padding multiplier. Used to write a packet.
        /// </summary>
        /// <param name="payload">The compressed payload.</param>
        /// <param name="blockSize">The block used used to determine the padding. Must be at least 8.</param>
        internal SshPacket(ByteWriter payload, int blockSize, uint sequenceNumber)
        {
            _buffer = payload.Bytes;

            // Generate padding to make the packet perfectly divisible by the block size.
            var padding = new byte[(2 * blockSize) - ((5 + payload.DataLength) % blockSize)];
            RandomGenerator.GetBytes(padding);

            ByteWriter.WriteUint(_buffer, PacketSizeIndex, (uint)(payload.DataLength + padding.Length + 1)); // Write packet length
            ByteWriter.WriteUint(_buffer, SequenceIndex, sequenceNumber); // Write sequence number

            _buffer[PaddingByteIndex] = (byte)padding.Length; // Write padding length
            Array.Copy(padding, 0, _buffer, payload.PaddingIndex, padding.Length); // Write padding

            // Payload offset skips (uint)sequence + (uint)size + (byte)padding length.
            // Payload length is the size of the compressedPayload.
            Payload = new PacketSegment(_buffer, 4 + 4 + 1, payload.DataLength);

            // Packet offset skips (uint)sequence
            // Packet length is the (uint)size + (byte)padding length + (byte[])payload + (byte[])padding. 
            Packet = new PacketSegment(_buffer, 4, 4 + 1 + payload.DataLength + padding.Length);

            // MacVerificatonBytes offset skips nothing.
            // MacVerificatonBytes length is the (uint) sequence + (uint)size + (byte)padding length + (byte[])payload + (byte[])padding. 
            MacVerificationBytes = new PacketSegment(_buffer, 0, 4 + 4 + 1 + payload.DataLength + padding.Length);

            // There is no server Mac result. This is a client packet, and the computation always produces a new array, so it doesn't make sense to copy it here.

            // This packet wont be read, but for consistency the read will be set to the payload offset.
            PayloadReader = ByteReader.ReadPacketSegment(Payload);
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
            _buffer = buffer;

            // Payload offset skips (uint)sequence + (uint)size + (byte)padding length.
            // Payload length = packet length - (uint)sequence + (uint)size + (byte)padding length.
            Payload = new PacketSegment(_buffer, 4 + 4 + 1, packetLength - 4 - 4 - 1);

            // Packet offset skips (uint)sequence
            // Packet length = packet length - (uint)sequence.
            Packet = new PacketSegment(_buffer, 4, packetLength - 4);

            // MacVerificatonBytes offset skips nothing.
            // MacVerificatonBytes length = packet length.
            MacVerificationBytes = new PacketSegment(_buffer, 0, packetLength);

            // Server MAC result skips the entire packetlength as the mac is at the end.
            ServerMacResult = new PacketSegment(_buffer, packetLength, hmacSize);

            PayloadReader = ByteReader.ReadPacketSegment(Payload);
        }
    }
}
