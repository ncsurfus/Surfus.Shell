namespace Surfus.Shell.Messages
{
    public interface IClientMessage
    {
        /// <summary>
        /// The type of SSH message this class represents.
        /// </summary>
        MessageType Type { get; }

        /// <summary>
        /// The byte identifier of the SSH message type.
        /// </summary>
        byte MessageId => (byte)Type;

        /// <summary>
        /// Returns the size in bytes of the payload (excluding the message type byte).
        /// </summary>
        int GetPayloadSize();

        /// <summary>
        /// Writes the payload (excluding the message type byte) into the provided writer.
        /// </summary>
        void WritePayload(ref SpanWriter writer);
    }
}
