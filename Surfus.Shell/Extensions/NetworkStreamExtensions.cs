using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.Extensions
{
    public static class NetworkStreamExtensions
    {
        internal static async Task WriteAsync(this NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            await stream.WriteAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task WriteAsync(this NetworkStream stream, byte buffer, CancellationToken cancellationToken)
        {
            await stream.WriteAsync(new[] { buffer }, 0, 1, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task WriteAsync(this NetworkStream stream, uint value, CancellationToken cancellationToken)
        {
            await stream.WriteAsync(value.GetBigEndianBytes(), cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<byte> ReadByteAsync(this NetworkStream stream, CancellationToken cancellationToken)
        {
            var buffer = new byte[1];
            var result = await stream.ReadAsync(buffer, 0, 1, cancellationToken).ConfigureAwait(false);
            if (result != 0)
            {
                return buffer[0];
            }

            throw new EndOfStreamException();
        }

        internal static async Task<byte[]> ReadBytesAsync(this NetworkStream stream, uint length, CancellationToken cancellationToken)
        {
            var buffer = new byte[length];
            var index = 0;
            while (index < buffer.Length)
            {
                var result = await stream.ReadAsync(buffer, index, buffer.Length - index, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (result == 0)
                {
                    throw new IOException("The underlying Socket is closed.");
                }
                index += result;
            }

            return buffer;
        }

        internal static async Task<uint> ReadUInt32Async(this NetworkStream stream, CancellationToken cancellationToken)
        {
            var data = await stream.ReadBytesAsync(4, cancellationToken).ConfigureAwait(false);
            return (uint)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);
        }
    }
}
