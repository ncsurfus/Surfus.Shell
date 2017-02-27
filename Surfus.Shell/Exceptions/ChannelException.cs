using System;

namespace Surfus.Shell.Exceptions
{
    public class ChannelException : SshException
    {
        public ChannelException(string message) : base(message)
        {
            
        }

        public ChannelException(string message, Exception innerException) : base(message, innerException)
        {

        }
    }
}
