using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell.Authentication
{
    internal class AgentAuth : IAuthMethod
    {
        private readonly SshAgentClient _agent;
        private readonly SshAgentKey _key;

        internal AgentAuth(SshAgentClient agent, SshAgentKey key)
        {
            _agent = agent;
            _key = key;
        }

        public async Task SendRequestAsync(SendMessageAsync send, string username, CancellationToken cancellationToken)
        {
            await send(new UaRequest(username, "ssh-connection", _key.KeyType, _key.KeyBlob, null), cancellationToken).ConfigureAwait(false);
        }

        public async Task HandleMessage60Async(SendMessageAsync send, string username, byte[] sessionIdentifier, MessageEvent messageEvent, CancellationToken cancellationToken)
        {
            var dataSize = sessionIdentifier.GetBinaryStringSize()
                + 1
                + username.GetStringSize()
                + "ssh-connection".GetAsciiStringSize()
                + "publickey".GetAsciiStringSize()
                + 1
                + _key.KeyType.GetAsciiStringSize()
                + _key.KeyBlob.GetBinaryStringSize();

            var dataWriter = new ByteWriter(dataSize);
            dataWriter.WriteBinaryString(sessionIdentifier);
            dataWriter.WriteByte(50);
            dataWriter.WriteString(username);
            dataWriter.WriteAsciiString("ssh-connection");
            dataWriter.WriteAsciiString("publickey");
            dataWriter.WriteByte(1);
            dataWriter.WriteAsciiString(_key.KeyType);
            dataWriter.WriteBinaryString(_key.KeyBlob);

            var signature = await _agent.SignAsync(_key.KeyBlob, dataWriter.Bytes, cancellationToken).ConfigureAwait(false);

            await send(new UaRequest(username, "ssh-connection", _key.KeyType, _key.KeyBlob, signature), cancellationToken).ConfigureAwait(false);
        }
    }
}
