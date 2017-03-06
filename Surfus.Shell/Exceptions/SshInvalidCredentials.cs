namespace Surfus.Shell.Exceptions
{
    public class SshInvalidCredentials : SshException
    {
        internal SshInvalidCredentials(string username) : base($"Failed to login to host with {username}")
        {

        }
    }
}
