namespace Surfus.Shell.Messages
{
    internal interface IClientMessage : IMessage
    {
        /// <summary>
        /// Gets the unencrypted SSH packet bytes.
        /// </summary>
        /// <returns></returns>
        ByteWriter GetByteWriter();

        /// <summary>
        /// Writes the message with the supplied byte writer.
        /// </summary>
        /// <returns></returns>
        void WriteMessage(SshPacketByteWriter writer);
    }
}
