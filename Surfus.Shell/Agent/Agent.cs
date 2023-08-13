using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Agent.Messages;

namespace Surfus.Shell.Agent
{
    public class Agent : IDisposable
    {
        private readonly byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
        private readonly byte SSH2_AGENTC_SIGN_REQUEST = 13;
        private Socket _socket;
        private NetworkStream _stream;

        public Agent(string path)
        {
            Path = path;
        }

        public Agent()
        {
            Path = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK")
                ?? throw new InvalidProgramException("SSH_AUTH_SOCK does not exist!");
        }

        public string Path { get; init; }

        public int MaxKeyBytes { get; init; } = 10_000_000;

        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            var endpoint = new UnixDomainSocketEndPoint(Path);
            await _socket.ConnectAsync(endpoint, cancellationToken);
            _stream = new NetworkStream(_socket, false);
        }

        public async Task<ReadOnlyMemory<SshAgentKey>> ReadKeysAsync(CancellationToken cancellationToken = default)
        {
            var result = await SendReceiveAsync(new byte[] { SSH2_AGENTC_REQUEST_IDENTITIES }, cancellationToken);
            var reader = new ByteReader(result);
            if (reader.ReadByte() != (byte)AgentMessageType.SSH2_AGENT_IDENTITIES_ANSWER)
            {
                throw new InvalidOperationException(
                    $"SSH Agent response is not an {nameof(AgentMessageType.SSH2_AGENT_IDENTITIES_ANSWER)}!"
                );
            }
            var answer = new Ssh2AgentRequestIdentitiesAnswer(reader, this);
            return answer.Keys;
        }

        public async Task<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default
        )
        {
            // Messsage Type + Size/Key Blob + Size/Data + Flags int)
            var writer = new ByteWriter(1 + 4 + publicKey.Length + 4 + data.Length + 4);
            writer.WriteByte(SSH2_AGENTC_SIGN_REQUEST);
            writer.WriteBinaryString(publicKey.Span);
            writer.WriteBinaryString(data.Span);
            writer.WriteUint(0);

            var result = await SendReceiveAsync(writer.Bytes, cancellationToken);
            var reader = new ByteReader(result);
            if (reader.ReadByte() != (byte)AgentMessageType.SSH2_AGENT_SIGN_RESPONSE)
            {
                throw new InvalidOperationException(
                    $"SSH Agent response is not an {nameof(AgentMessageType.SSH2_AGENT_SIGN_RESPONSE)}!"
                );
            }
            var signedData = reader.ReadBinaryString();
            return signedData;
        }

        public async Task<byte[]> SendReceiveAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            // Send the size of the data, and the data
            var writer = new ByteWriter(4);
            writer.WriteUint((uint)data.Length);
            await _stream.WriteAsync(writer.Bytes, cancellationToken);
            await _stream.WriteAsync(data, cancellationToken);
            await _stream.FlushAsync(cancellationToken);

            // Get the size of their packet
            var responseSizeBuffer = new byte[4];
            await _stream.ReadExactlyAsync(responseSizeBuffer, cancellationToken);
            var responseSize = new ByteReader(responseSizeBuffer).ReadUInt32();

            // Verify the size is reasonable
            // Need to investigate what "resonable" means here.
            if (responseSize > MaxKeyBytes)
            {
                throw new InvalidOperationException("SSH Agent response is greater than 10MB");
            }
            else if (responseSize < 1)
            {
                throw new InvalidOperationException("SSH Agent response is less than 1 byte");
            }

            // Read the payload
            var responseBuffer = new byte[responseSize];
            await _stream.ReadExactlyAsync(responseBuffer, cancellationToken);
            return responseBuffer;
        }

        public void Dispose()
        {
            _socket?.Close();
            _stream?.Dispose();
        }
    }
}

