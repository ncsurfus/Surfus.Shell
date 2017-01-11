using System;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Exceptions
{
    public class SshInvalidMessageException : SshException
    {
        internal SshInvalidMessageException(MessageType messageType) : base($"Server sent corrupt '{messageType}' message.")
        {
            MessageType = messageType.ToString();
            MessageCode = (byte) messageType;
        }

        public SshInvalidMessageException(MessageType messageType, Exception innerException) : base($"Server sent corrupt '{messageType}' message.", innerException)
        {
            MessageType = messageType.ToString();
            MessageCode = (byte)messageType;
        }

        public string MessageType { get; }
        public byte MessageCode { get; }
    }
}
