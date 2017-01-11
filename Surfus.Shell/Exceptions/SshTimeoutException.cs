using System;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Exceptions
{
    public class SshTimeoutException : SshException
    {
        internal SshTimeoutException(MessageType messageType) : base($"Server failed to respond to {messageType} in a timely manner.")
        {
            MessageType = messageType.ToString();
            MessageCode = (byte) messageType;
        }

        public SshTimeoutException(MessageType messageType, Exception innerException) : base($"Server failed to respond to {messageType} in a timely manner.", innerException)
        {  
            MessageType = messageType.ToString();
            MessageCode = (byte)messageType;
        }

        public string MessageType { get; }
        public byte MessageCode { get; }
    }
}
