using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages
{
    public class Disconnect : IMessage
    {
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        public enum DisconnectReason : uint
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

        public Disconnect(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                Reason = (DisconnectReason) stream.ReadUInt32();
                Description = stream.ReadString();
                LanguageTag = stream.ReadString();
            }
        }

        public Disconnect(DisconnectReason disconnectReason, string description, string languageTag = null)
        {
            Reason = disconnectReason;
            Description = description;
            LanguageTag = languageTag;
        }

        public uint ReasonId => (uint)Reason;
        public DisconnectReason Reason { get; }
        public string Description { get; }
        public string LanguageTag { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_DISCONNECT;
        public byte MessageId => (byte)Type;

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
