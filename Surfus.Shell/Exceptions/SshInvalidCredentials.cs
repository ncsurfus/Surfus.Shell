namespace Surfus.Shell.Exceptions
{
    /// <summary>
    /// An exception thrown when the server rejects the supplied credentials.
    /// </summary>
    public class SshInvalidCredentials : SshAuthenticationException
    {
        /// <summary>
        /// An exception thrown when the server rejects the supplied credentials.
        /// </summary>
        public SshInvalidCredentials() : base("The credentials were rejected.")
        {

        }
    }
}
