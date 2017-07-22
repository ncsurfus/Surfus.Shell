namespace Surfus.Shell.Messages
{
    public interface IMessage
    {
        /// <summary>
        /// The type of SSH message this class represents.
        /// </summary>
        MessageType Type { get; }

        /// <summary>
        /// The byte identified of the SSH message type.
        /// </summary>
        byte MessageId { get; }
    }
}
