using System;

namespace Surfus.Shell.Exceptions
{
    public class SshException : Exception
    {
        public SshException(string message) : base(message)
        {

        }

        public SshException(string message, Exception innerException) : base(message, innerException)
        {

        }
    }
}
