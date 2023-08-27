namespace Surfus.Shell.Exceptions
{
    /// <summary>
    /// An exception thrown when there is an authentication issue.
    /// </summary>
    public class SshAuthenticationException : SshException
    {
        internal const string UnexpectedAuthenticationMessage = "There was an unexpected authentication message from the server.";

        /// <summary>
        /// An exception thrown when there is an authentication issue.
        /// </summary>
        public SshAuthenticationException(string message)
            : base(message) { }
    }
}
