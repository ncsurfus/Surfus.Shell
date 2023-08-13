namespace Surfus.Shell.Agent.Messages
{
    public interface IAgentMessage
    {
        /// <summary>
        /// The type of SSH Agent message this class represents.
        /// </summary>
        AgentMessageType Type { get; }
    }
}
