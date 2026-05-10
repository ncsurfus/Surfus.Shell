using System;
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

        public Task<IClientMessage> CreateRequestAsync(string username, CancellationToken cancellationToken) =>
            Task.FromResult<IClientMessage>(new UaRequest(username, "ssh-connection", _key.KeyType, _key.KeyBlob, null));

        public async Task<IClientMessage?> HandleMessage60Async(
            string username,
            ReadOnlyMemory<byte> sessionIdentifier,
            MessageEvent messageEvent,
            CancellationToken cancellationToken
        )
        {
            var dataSize =
                sessionIdentifier.GetBinaryStringSize()
                + 1
                + username.GetStringSize()
                + "ssh-connection".GetAsciiStringSize()
                + "publickey".GetAsciiStringSize()
                + 1
                + _key.KeyType.GetAsciiStringSize()
                + _key.KeyBlob.GetBinaryStringSize();

            var w = new ByteWriter(dataSize);
            w.WriteBinaryString(sessionIdentifier);
            w.WriteByte(50);
            w.WriteString(username);
            w.WriteAsciiString("ssh-connection");
            w.WriteAsciiString("publickey");
            w.WriteByte(1);
            w.WriteAsciiString(_key.KeyType);
            w.WriteBinaryString(_key.KeyBlob);

            var signature = await _agent.SignAsync(_key.KeyBlob, w.Bytes, cancellationToken).ConfigureAwait(false);
            return new UaRequest(username, "ssh-connection", _key.KeyType, _key.KeyBlob, signature);
        }
    }
}
