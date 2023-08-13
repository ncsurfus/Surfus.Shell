using System.Threading.Tasks;

namespace Surfus.Shell.Agent.Messages
{
    public class Ssh2AgentRequestIdentities : IAgentClientMessage
    {
        public AgentMessageType Type { get; } = AgentMessageType.SSH2_AGENTC_REQUEST_IDENTITIES;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(4);
            writer.WriteByte((byte)Type);
            return writer;
        }
    }
}
