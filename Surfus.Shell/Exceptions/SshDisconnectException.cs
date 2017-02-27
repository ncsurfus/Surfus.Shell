using Surfus.Shell.Messages;

namespace Surfus.Shell.Exceptions
{
    public class SshDisconnectException : SshException
    {
        internal SshDisconnectException(Disconnect.DisconnectReason reason) : base(reason.ToString())
        {
            Reason = reason.ToString();
            ReasonCode = (uint) reason;
            if (reason == Disconnect.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION)
            {
                Graceful = true;
            }
        }

        public bool Graceful { get; }
        public string Reason { get; }
        public uint ReasonCode { get; }
    }
}
