using System;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Exceptions
{
    public class SshUnexpectedMessage : SshException
    {
        internal SshUnexpectedMessage(MessageType message) : base($"Received unexpected message '{message}'.")
        {
            MessageType = message.ToString();
            MessageCode = (byte)message;
        }

        public SshUnexpectedMessage(MessageType message, Exception innerException) : base($"Received unexpected message '{message}'.", innerException)
        {
            MessageType = message.ToString();
            MessageCode = (byte)message;
        }

        public string MessageType { get; }
        public byte MessageCode { get; }
    }
}
