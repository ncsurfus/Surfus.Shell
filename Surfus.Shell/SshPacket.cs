using System;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;

namespace Surfus.Shell
{
    internal class SshPacket
    {
        private static readonly RandomNumberGenerator RandomGenerator = RandomNumberGenerator.Create();
        public readonly uint Length;
        public readonly byte[] Padding;
        public readonly byte[] Payload;
        public readonly byte[] Raw;

        public SshPacket(byte[] compressedPayload, int paddingMultiplier)
        {
            // Generate padding
            var paddingLength = -((5 + compressedPayload.Length) % paddingMultiplier) + paddingMultiplier * 2;
            var padding = new byte[paddingLength <= 255 ? paddingLength : paddingLength - paddingMultiplier];
            RandomGenerator.GetBytes(padding);

            if (padding.Length > byte.MaxValue) throw new ArgumentException($"{nameof(padding)} cannot be greater than {byte.MaxValue}");

            Raw = new byte[5 + compressedPayload.Length + padding.Length];

            // Write Packet Length into 'Raw'
            Length = (uint)(compressedPayload.Length + padding.Length + 1);
            Array.Copy(Length.GetBigEndianBytes(), 0, Raw, 0, 4);

            // Write Padding Length into 'Raw'
            Raw[4] = (byte)padding.Length;

            // Write Payload into 'Raw'
            Payload = compressedPayload;
            Array.Copy(Payload, 0, Raw, 5, Payload.Length);

            // Write Padding into 'Raw'
            Padding = padding;
            Array.Copy(Padding, 0, Raw, 5 + Payload.Length, Padding.Length);
        }

        public SshPacket(byte[] firstBlock, byte[] secondBlock)
        {
            Raw = new byte[firstBlock.Length + secondBlock.Length];
            Array.Copy(firstBlock, 0, Raw, 0, firstBlock.Length);
            Array.Copy(secondBlock, 0, Raw, firstBlock.Length, secondBlock.Length);

            Length = GetLength();
            Padding = new byte[GetPaddingLength()];
            Payload = new byte[GetPayloadLength()];

            // Payload starts at index 5
            Array.Copy(Raw, 5, Payload, 0, Payload.Length);

            // Padding starts at index 5 + payload.Length
            Array.Copy(Raw, 5 + Payload.Length, Padding, 0, Padding.Length);
        }

        private uint GetLength()
        {
            // Raw index: [0, 1, 2, 3]
            return Raw.FromBigEndianToUint();
        }

        private byte GetPaddingLength()
        {
            // Raw index: [4]
            return Raw[4];
        }

        private uint GetPayloadLength()
        {
            return (uint) (Length - Padding.Length - 1);
        }
    }
}
