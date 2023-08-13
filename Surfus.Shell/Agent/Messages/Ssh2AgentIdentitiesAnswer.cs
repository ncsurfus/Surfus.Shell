using System;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.Agent.Messages
{
    public class Ssh2AgentRequestIdentitiesAnswer : IAgentMessage
    {
        public AgentMessageType Type { get; } = AgentMessageType.SSH2_AGENT_IDENTITIES_ANSWER;

        public ReadOnlyMemory<SshAgentKey> Keys { get; }

        internal Ssh2AgentRequestIdentitiesAnswer(ByteReader reader, Agent agent)
        {
            var totalKeys = reader.ReadUInt32();
            var keys = new SshAgentKey[totalKeys];
            for (var i = 0; i < keys.Length; i++)
            {
                var publicKey = reader.ReadBinaryString();
                var keyReader = new ByteReader(publicKey);
                var keyType = keyReader.ReadAsciiString();
                var comment = reader.ReadString();
                async Task<ReadOnlyMemory<byte>> signAsync(ReadOnlyMemory<byte> data, CancellationToken token)
                {
                    return await agent.SignAsync(publicKey, data, token);
                }
                keys[i] = new SshAgentKey(publicKey, keyType, signAsync, comment);
            }
            Keys = keys;
        }
    }
}
