using System.Threading.Tasks;

namespace Surfus.Shell.Agent.Messages
{
    public interface IAgentClientMessage : IAgentMessage
    {
        /// <summary>
        /// Gets the packet bytes.
        /// </summary>
        ByteWriter GetByteWriter();
    }
}
