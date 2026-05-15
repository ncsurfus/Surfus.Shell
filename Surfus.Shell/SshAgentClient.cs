using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    /// <summary>
    /// Represents a public key held by the SSH agent.
    /// </summary>
    public record SshAgentKey
    {
        public ReadOnlyMemory<byte> KeyBlob { get; }
        public string Comment { get; }
        public string KeyType { get; }

        internal SshAgentKey(ReadOnlyMemory<byte> keyBlob, string comment)
        {
            KeyBlob = keyBlob;
            Comment = comment;
            var reader = new SpanReader(keyBlob.Span);
            KeyType = reader.ReadAsciiString();
        }
    }

    /// <summary>
    /// Client for the SSH agent protocol (RFC 4253 / draft-miller-ssh-agent).
    /// Communicates over a Unix domain socket specified by SSH_AUTH_SOCK.
    /// </summary>
    public sealed class SshAgentClient : IDisposable
    {
        private const byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
        private const byte SSH_AGENT_IDENTITIES_ANSWER = 12;
        private const byte SSH_AGENTC_SIGN_REQUEST = 13;
        private const byte SSH_AGENT_SIGN_RESPONSE = 14;
        private const byte SSH_AGENT_FAILURE = 5;

        private readonly Socket? _socket;
        private readonly Stream _stream;

        private SshAgentClient(Socket socket)
        {
            _socket = socket;
            _stream = new NetworkStream(socket, ownsSocket: false);
        }

        /// <summary>
        /// Creates an SSH agent client using the provided stream.
        /// </summary>
        public SshAgentClient(Stream stream)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        }

        /// <summary>
        /// Connects to the SSH agent at the given socket path, or SSH_AUTH_SOCK if not specified.
        /// </summary>
        public static async Task<SshAgentClient> ConnectAsync(string? socketPath = null, CancellationToken cancellationToken = default)
        {
            socketPath ??=
                Environment.GetEnvironmentVariable("SSH_AUTH_SOCK") ?? throw new InvalidOperationException("SSH_AUTH_SOCK is not set.");

            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
            return new SshAgentClient(socket);
        }

        /// <summary>
        /// Lists all keys held by the agent.
        /// </summary>
        public async Task<List<SshAgentKey>> ListKeysAsync(CancellationToken cancellationToken = default)
        {
            await SendAsync([SSH_AGENTC_REQUEST_IDENTITIES], cancellationToken).ConfigureAwait(false);
            var response = await ReceiveAsync(cancellationToken).ConfigureAwait(false);
            var reader = new SpanReader(response);

            var type = reader.ReadByte();
            if (type == SSH_AGENT_FAILURE)
            {
                throw new Exceptions.SshException("SSH agent returned failure for identity request.");
            }
            if (type != SSH_AGENT_IDENTITIES_ANSWER)
            {
                throw new Exceptions.SshException($"Unexpected agent response type: {type}");
            }

            var count = (int)reader.ReadUInt32();
            var keys = new List<SshAgentKey>(count);
            for (var i = 0; i < count; i++)
            {
                var keyBlob = reader.ReadBinaryString().ToArray();
                var comment = reader.ReadUtf8String();
                keys.Add(new SshAgentKey(keyBlob, comment));
            }
            return keys;
        }

        /// <summary>
        /// Asks the agent to sign data with the specified key.
        /// </summary>
        public async Task<byte[]> SignAsync(
            ReadOnlyMemory<byte> keyBlob,
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken = default
        )
        {
            // Build: byte type + string key_blob + string data + uint32 flags
            var size = 1 + 4 + keyBlob.Length + 4 + data.Length + 4;
            var buf = new byte[size];
            var pos = 0;
            buf[pos++] = SSH_AGENTC_SIGN_REQUEST;
            WriteUInt32(buf, ref pos, (uint)keyBlob.Length);
            keyBlob.Span.CopyTo(buf.AsSpan(pos));
            pos += keyBlob.Length;
            WriteUInt32(buf, ref pos, (uint)data.Length);
            data.Span.CopyTo(buf.AsSpan(pos));
            pos += data.Length;
            // TODO: flags=0 means SSH_AGENT_RSA_SHA2_256/512 are not requested, so the agent
            // defaults to SHA-1 for RSA keys. For rsa-sha2-256 set flags=2, for rsa-sha2-512 set flags=4.
            // This requires knowing which algorithm was negotiated.
            WriteUInt32(buf, ref pos, 0); // flags

            await SendAsync(buf, cancellationToken).ConfigureAwait(false);
            var response = await ReceiveAsync(cancellationToken).ConfigureAwait(false);
            var reader = new SpanReader(response);

            var type = reader.ReadByte();
            if (type == SSH_AGENT_FAILURE)
            {
                throw new Exceptions.SshException("SSH agent refused to sign.");
            }
            if (type != SSH_AGENT_SIGN_RESPONSE)
            {
                throw new Exceptions.SshException($"Unexpected agent response type: {type}");
            }

            return reader.ReadBinaryString().ToArray();
        }

        private async Task SendAsync(byte[] payload, CancellationToken cancellationToken)
        {
            var lengthBuf = new byte[4];
            WriteUInt32(lengthBuf, 0, (uint)payload.Length);
            await _stream.WriteAsync(lengthBuf.AsMemory(), cancellationToken).ConfigureAwait(false);
            await _stream.WriteAsync(payload.AsMemory(), cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        private async Task<byte[]> ReceiveAsync(CancellationToken cancellationToken)
        {
            var lengthBuf = new byte[4];
            await ReadExactAsync(lengthBuf, cancellationToken).ConfigureAwait(false);
            var length = (int)BinaryPrimitives.ReadUInt32BigEndian(lengthBuf.AsSpan(0));
            if (length > 256 * 1024)
            {
                throw new Exceptions.SshException("Agent response too large.");
            }
            var payload = new byte[length];
            await ReadExactAsync(payload, cancellationToken).ConfigureAwait(false);
            return payload;
        }

        private async Task ReadExactAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var read = await _stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new Exceptions.SshException("SSH agent connection closed.");
                }
                offset += read;
            }
        }

        private static void WriteUInt32(byte[] buf, ref int pos, uint value)
        {
            buf[pos++] = (byte)(value >> 24);
            buf[pos++] = (byte)(value >> 16);
            buf[pos++] = (byte)(value >> 8);
            buf[pos++] = (byte)value;
        }

        private static void WriteUInt32(byte[] buf, int pos, uint value)
        {
            buf[pos] = (byte)(value >> 24);
            buf[pos + 1] = (byte)(value >> 16);
            buf[pos + 2] = (byte)(value >> 8);
            buf[pos + 3] = (byte)value;
        }

        public void Dispose()
        {
            _stream.Dispose();
            _socket?.Dispose();
        }
    }
}
