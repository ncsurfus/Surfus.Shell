namespace Surfus.Shell.Agent.Messages
{
    /// <summary>
    /// SSH Agent Message Types
    /// </summary>
    public enum AgentMessageType : byte
    {
        /// <summary>
        /// Message to request identities.
        /// </summary>
        SSH2_AGENTC_REQUEST_IDENTITIES = 11,

        /// <summary>
        /// Message that contains the SSH identities.
        /// </summary>
        SSH2_AGENT_IDENTITIES_ANSWER = 12,

        /// <summary>
        /// Message requesting the agent to sign a request.
        /// </summary>
        SSH2_AGENTC_SIGN_REQUEST = 13,

        /// <summary>
        /// Message that contains the signed request.
        /// </summary>
        SSH2_AGENT_SIGN_RESPONSE = 14,
    }
}
