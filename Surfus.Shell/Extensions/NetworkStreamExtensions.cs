using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.Extensions
{
    public static class NetworkStreamExtensions
    {
        internal static Task WriteAsync(this NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            return stream.WriteAsync(buffer, 0, buffer.Length, cancellationToken);
        }

        internal static async Task<byte[]> ReadBytesAsync(this NetworkStream stream, uint length, CancellationToken cancellationToken)
        {
            var buffer = new byte[length];
            var index = 0;
            while (index < buffer.Length)
            {
                var result = await stream.ReadAsync(buffer, index, buffer.Length - index, cancellationToken).ConfigureAwait(false);
                if (result == 0)
                {
                    throw new IOException("The underlying Socket is closed.");
                }
                index += result;
            }

            return buffer;
        }

        internal static Task<byte[]> ReadFourBytesAsync(this NetworkStream stream, CancellationToken cancellationToken)
        {
            return stream.ReadBytesAsync(16, cancellationToken);
        }
    }
}
