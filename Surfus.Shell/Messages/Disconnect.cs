using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages
{
    internal class Disconnect : IClientMessage
    {
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        internal enum DisconnectReason : uint
        {
            SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1, 
            SSH_DISCONNECT_PROTOCOL_ERROR = 2, 
            SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3, 
            SSH_DISCONNECT_RESERVED = 4, 
            SSH_DISCONNECT_MAC_ERROR = 5, 
            SSH_DISCONNECT_COMPRESSION_ERROR = 6, 
            SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7, 
            SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8, 
            SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9, 
            SSH_DISCONNECT_CONNECTION_LOST = 10, 
            SSH_DISCONNECT_BY_APPLICATION = 11, 
            SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12, 
            SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13, 
            SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14, 
            SSH_DISCONNECT_ILLEGAL_USER_NAME = 15
        }

        internal Disconnect(SshPacket packet)
        {
            Reason = (DisconnectReason)packet.Reader.ReadUInt32();
            Description = packet.Reader.ReadString();
            LanguageTag = packet.Reader.ReadString();
        }

        internal Disconnect(DisconnectReason disconnectReason, string description, string languageTag = null)
        {
            Reason = disconnectReason;
            Description = description;
            LanguageTag = languageTag;
        }

        internal uint ReasonId => (uint)Reason;
        internal DisconnectReason Reason { get; }
        internal string Description { get; }
        internal string LanguageTag { get; }

        /// <summary>
        /// The type of SSH message this class represents.
        /// </summary>
        public MessageType Type { get; } = MessageType.SSH_MSG_DISCONNECT;

        /// <summary>
        /// The byte identified of the SSH message type.
        /// </summary>
        public byte MessageId => (byte)Type;

        /// <summary>
        /// Gets the unencrypted SSH packet bytes.
        /// </summary>
        /// <returns></returns>
        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteUInt(ReasonId);
                memoryStream.WriteString(Description);
                memoryStream.WriteString(LanguageTag);
                return memoryStream.ToArray();
            }
        }
    }
}
