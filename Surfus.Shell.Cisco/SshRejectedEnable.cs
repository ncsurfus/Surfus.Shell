using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Cisco.Exceptions
{
    /// <summary>
    /// An exception thrown when the server rejected the enable password.
    /// </summary>
    public class SshRejectedEnable : SshAuthenticationException
    {
        /// <summary>
        /// An exception thrown when the server rejected the enable password.
        /// </summary>
        public SshRejectedEnable(string message) : base(message)
        {

        }
    }
}
