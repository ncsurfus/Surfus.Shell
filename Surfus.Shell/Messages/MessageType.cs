namespace Surfus.Shell.Messages
{
    /// <summary>
    /// SSH Message Types
    /// </summary>
    public enum MessageType : byte
    {
        /// <summary>
        /// Disconnect Message. This message is used to terminate the SSH connection.
        /// </summary>
        SSH_MSG_DISCONNECT = 1,

        /// <summary>
        /// Ignore Message. The recipient device should ignore this message.
        /// </summary>
        SSH_MSG_IGNORE = 2,

        /// <summary>
        /// Unimplemented Message. If the recipient does not implement a message, the recipient should reply with an unimplemented message.
        /// </summary>
        SSH_MSG_UNIMPLEMENTED = 3,

        /// <summary>
        /// Debug Message. Can be logged or ignored by the recipient.
        /// </summary>
        SSH_MSG_DEBUG = 4,

        /// <summary>
        /// Service Request Message. Sent by the client to request a service from the server.
        /// </summary>
        SSH_MSG_SERVICE_REQUEST = 5,

        /// <summary>
        /// Service Accept Message. Sent by the server to notify the client the service request has been granted.
        /// </summary>
        SSH_MSG_SERVICE_ACCEPT = 6,

        /// <summary>
        /// Key Exchange Initiate Message. Used to initiate a key exchange.
        /// </summary>
        SSH_MSG_KEXINIT = 20,

        /// <summary>
        /// New Keys Message. After this message is sent both parties will switchover to the new crypto as determiend
        /// </summary>
        SSH_MSG_NEWKEYS = 21,

        /// <summary>
        /// The meaning of this message is determined by the key exchange method.
        /// </summary>
        SSH_MSG_KEX_Exchange_30 = 30,

        /// <summary>
        /// The meaning of this message is determined by the key exchange method.
        /// </summary>
        SSH_MSG_KEX_Exchange_31 = 31,

        /// <summary>
        /// The meaning of this message is determined by the key exchange method.
        /// </summary>
        SSH_MSG_KEX_Exchange_32 = 32,

        /// <summary>
        /// The meaning of this message is determined by the key exchange method.
        /// </summary>
        SSH_MSG_KEX_Exchange_33 = 33,

        /// <summary>
        /// The meaning of this message is determined by the key exchange method.
        /// </summary>
        SSH_MSG_KEX_Exchange_34 = 34,

        /// <summary>
        /// Sent by the client to attempt authentication with the server.
        /// </summary>
        SSH_MSG_USERAUTH_REQUEST = 50,

        /// <summary>
        /// Sent by the server to reject authentication.
        /// </summary>
        SSH_MSG_USERAUTH_FAILURE = 51,

        /// <summary>
        /// Sent by the server to accept authentication.
        /// </summary>
        SSH_MSG_USERAUTH_SUCCESS = 52,

        /// <summary>
        /// Sent by the server to preferably show a message to the user.
        /// </summary>
        SSH_MSG_USERAUTH_BANNER = 53,

        /// <summary>
        /// Sent by the server to authenticate a user with keyboard-interactive authentication.
        /// </summary>
        SSH_MSG_USERAUTH_INFO_REQUEST = 60,

        /// <summary>
        /// Sent by the client to authenticate with keyboard-interactive authentication.
        /// </summary>
        SSH_MSG_USERAUTH_INFO_RESPONSE = 61,

        /// <summary>
        /// Sent by the client to globally request a service.
        /// </summary>
        SSH_MSG_GLOBAL_REQUEST = 80,

        /// <summary>
        /// The ss h_ ms g_ reques t_ success.
        /// </summary>
        SSH_MSG_REQUEST_SUCCESS = 81, 
        SSH_MSG_REQUEST_FAILURE = 82, 
        SSH_MSG_CHANNEL_OPEN = 90, 
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91, 
        SSH_MSG_CHANNEL_OPEN_FAILURE = 92, 
        SSH_MSG_CHANNEL_WINDOW_ADJUST = 93, 
        SSH_MSG_CHANNEL_DATA = 94, 
        SSH_MSG_CHANNEL_EXTENDED_DATA = 95, 
        SSH_MSG_CHANNEL_EOF = 96, 
        SSH_MSG_CHANNEL_CLOSE = 97, 
        SSH_MSG_CHANNEL_REQUEST = 98, 
        SSH_MSG_CHANNEL_SUCCESS = 99, 
        SSH_MSG_CHANNEL_FAILURE = 100
    }
}
