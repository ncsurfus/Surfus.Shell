using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell;

/// <summary>
/// Result of the SSH version exchange.
/// </summary>
internal readonly record struct VersionExchangeResult(string ServerVersion, IReadOnlyList<string> BannerLines);

/// <summary>
/// Performs the SSH version exchange per RFC 4253 §4.2.
/// Sends the client version immediately, then reads lines until the server version is found.
/// </summary>
internal static class SshVersionExchange
{
    private const int MaxLineLength = 255;
    private const int MaxBannerLines = 1024;

    public static async Task<VersionExchangeResult> ExchangeAsync(
        Stream stream, string clientVersion, CancellationToken cancellationToken)
    {
        // Send client version immediately to reduce round-trip latency.
        var clientBytes = Encoding.ASCII.GetBytes(clientVersion + "\r\n");
        await stream.WriteAsync(clientBytes.AsMemory(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Read lines until we find the version string.
        var bannerLines = new List<string>();
        var buffer = new byte[MaxLineLength + 1];
        var pos = 0;

        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(pos, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new SshException("Failed to exchange SSH version. Connection was closed.");
            }

            if (buffer[pos] == '\n')
            {
                // Strip \r\n or \n
                var end = pos > 0 && buffer[pos - 1] == '\r' ? pos - 1 : pos;

                if (end >= 4 && buffer[0] == 'S' && buffer[1] == 'S' && buffer[2] == 'H' && buffer[3] == '-')
                {
                    if (!IsValidVersionString(buffer.AsSpan(0, end)))
                    {
                        throw new SshException("Server version contains invalid characters.");
                    }
                    var version = Encoding.ASCII.GetString(buffer, 0, end);
                    if (!version.StartsWith("SSH-2.0-") && !version.StartsWith("SSH-1.99-"))
                    {
                        throw new SshException("Server version is not supported.");
                    }
                    return new VersionExchangeResult(version, bannerLines);
                }

                bannerLines.Add(Encoding.UTF8.GetString(buffer, 0, end));
                if (bannerLines.Count >= MaxBannerLines)
                {
                    throw new SshException("Too many banner lines before version string.");
                }
                pos = 0;
                continue;
            }

            pos++;
            if (pos > MaxLineLength)
            {
                throw new SshException($"Failed to exchange SSH version. Line exceeds {MaxLineLength} bytes.");
            }
        }
    }

    private static bool IsValidVersionString(ReadOnlySpan<byte> bytes)
    {
        foreach (var b in bytes)
        {
            if (b < 0x20 || b > 0x7E)
                return false;
        }
        return true;
    }
}
