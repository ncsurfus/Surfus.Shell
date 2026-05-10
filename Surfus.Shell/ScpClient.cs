using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell
{
    /// <summary>
    /// Provides SCP file transfer over an SSH connection.
    /// </summary>
    public sealed class ScpClient
    {
        private readonly SshClient _client;

        /// <summary>
        /// When true, passes -O to scp to force legacy SCP protocol (required on OpenSSH 9+ which defaults to SFTP).
        /// Default is true.
        /// </summary>
        public bool UseLegacyProtocolFlag { get; init; } = true;

        public ScpClient(SshClient client)
        {
            _client = client;
        }

        /// <summary>
        /// Uploads a file to the remote server.
        /// </summary>
        /// <param name="localPath">Local file path to upload.</param>
        /// <param name="remotePath">Remote destination path.</param>
        /// <param name="permissions">Unix file permissions (default 0644).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task UploadAsync(string localPath, string remotePath, string permissions = "0644", CancellationToken cancellationToken = default)
        {
            await using var stream = File.OpenRead(localPath);
            var fileName = Path.GetFileName(remotePath);
            await UploadAsync(stream, stream.Length, remotePath, fileName, permissions, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Uploads a stream to the remote server as a file.
        /// </summary>
        /// <param name="source">Source stream to upload.</param>
        /// <param name="length">Length of the data to upload.</param>
        /// <param name="remotePath">Remote destination path.</param>
        /// <param name="fileName">File name on the remote side.</param>
        /// <param name="permissions">Unix file permissions (default 0644).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task UploadAsync(Stream source, long length, string remotePath, string fileName = null, string permissions = "0644", CancellationToken cancellationToken = default)
        {
            fileName ??= Path.GetFileName(remotePath);
            var remoteDir = GetDirectoryPart(remotePath);

            var command = await _client.CreateCommandAsync(cancellationToken).ConfigureAwait(false);
            await using (command)
            {
                var scpFlags = UseLegacyProtocolFlag ? "-O -t" : "-t";
                await command.StartAsync($"scp {scpFlags} {EscapeShellArg(remotePath)}", cancellationToken).ConfigureAwait(false);

                await ReadResponseAsync(command.StandardOutput, cancellationToken).ConfigureAwait(false);

                // Send file header: C<permissions> <size> <filename>\n
                var header = Encoding.UTF8.GetBytes($"C{permissions} {length} {fileName}\n");
                await command.StandardInput.WriteAsync(header, cancellationToken).ConfigureAwait(false);
                await command.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);

                await ReadResponseAsync(command.StandardOutput, cancellationToken).ConfigureAwait(false);

                // Send file data
                var buffer = new byte[32768];
                var remaining = length;
                while (remaining > 0)
                {
                    var toRead = (int)Math.Min(remaining, buffer.Length);
                    var bytesRead = await source.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0)
                    {
                        throw new SshException("Source stream ended before expected length was reached.");
                    }
                    await command.StandardInput.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                    remaining -= bytesRead;
                }

                // Send completion byte
                await command.StandardInput.WriteAsync(new byte[] { 0 }, cancellationToken).ConfigureAwait(false);
                await command.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);

                await ReadResponseAsync(command.StandardOutput, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Downloads a file from the remote server.
        /// </summary>
        /// <param name="remotePath">Remote file path to download.</param>
        /// <param name="localPath">Local destination path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task DownloadAsync(string remotePath, string localPath, CancellationToken cancellationToken = default)
        {
            await using var stream = File.Create(localPath);
            await DownloadAsync(remotePath, stream, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Downloads a file from the remote server into a stream.
        /// </summary>
        /// <param name="remotePath">Remote file path to download.</param>
        /// <param name="destination">Destination stream to write to.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task DownloadAsync(string remotePath, Stream destination, CancellationToken cancellationToken = default)
        {
            var command = await _client.CreateCommandAsync(cancellationToken).ConfigureAwait(false);
            await using (command)
            {
                var scpFlags = UseLegacyProtocolFlag ? "-O -f" : "-f";
                await command.StartAsync($"scp {scpFlags} {EscapeShellArg(remotePath)}", cancellationToken).ConfigureAwait(false);

                // Send ready signal
                await command.StandardInput.WriteAsync(new byte[] { 0 }, cancellationToken).ConfigureAwait(false);
                await command.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);

                // Read file header: C<permissions> <size> <filename>\n
                var headerLine = await ReadLineAsync(command.StandardOutput, cancellationToken).ConfigureAwait(false);
                if (headerLine.Length == 0 || headerLine[0] != 'C')
                {
                    throw new SshException($"Unexpected SCP response: {headerLine}");
                }

                var parts = headerLine.Substring(1).Split(' ', 3);
                if (parts.Length < 3 || !long.TryParse(parts[1], out var fileSize))
                {
                    throw new SshException($"Invalid SCP file header: {headerLine}");
                }

                // Acknowledge header
                await command.StandardInput.WriteAsync(new byte[] { 0 }, cancellationToken).ConfigureAwait(false);
                await command.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);

                // Read file data
                var buffer = new byte[32768];
                var remaining = fileSize;
                while (remaining > 0)
                {
                    var toRead = (int)Math.Min(remaining, buffer.Length);
                    var bytesRead = await command.StandardOutput.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0)
                    {
                        throw new SshException("Connection closed before file transfer completed.");
                    }
                    await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                    remaining -= bytesRead;
                }

                // Read completion byte (0x00)
                var completionBuf = new byte[1];
                var n = await command.StandardOutput.ReadAsync(completionBuf, cancellationToken).ConfigureAwait(false);
                if (n == 1 && completionBuf[0] != 0)
                {
                    throw new SshException("SCP transfer failed: remote error.");
                }

                // Acknowledge completion
                await command.StandardInput.WriteAsync(new byte[] { 0 }, cancellationToken).ConfigureAwait(false);
                await command.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        private static async Task ReadResponseAsync(Stream stdout, CancellationToken cancellationToken)
        {
            var buf = new byte[1];
            var n = await stdout.ReadAsync(buf, cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                throw new SshException("SCP: unexpected end of stream.");
            }

            switch (buf[0])
            {
                case 0: // OK
                    return;
                case 1: // Warning
                case 2: // Error
                    var msg = await ReadLineAsync(stdout, cancellationToken).ConfigureAwait(false);
                    throw new SshException($"SCP error: {msg}");
                default:
                    throw new SshException($"SCP: unexpected response byte: {buf[0]}");
            }
        }

        private static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
        {
            var sb = new StringBuilder();
            var buf = new byte[1];
            while (true)
            {
                var n = await stream.ReadAsync(buf, cancellationToken).ConfigureAwait(false);
                if (n == 0 || buf[0] == '\n')
                {
                    break;
                }
                sb.Append((char)buf[0]);
            }
            return sb.ToString();
        }

        private static string EscapeShellArg(string arg)
        {
            return "'" + arg.Replace("'", "'\\''") + "'";
        }

        private static string GetDirectoryPart(string path)
        {
            var lastSlash = path.LastIndexOf('/');
            return lastSlash > 0 ? path.Substring(0, lastSlash) : ".";
        }
    }
}
