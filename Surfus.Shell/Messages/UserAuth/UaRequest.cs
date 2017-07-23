using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaRequest : IClientMessage
    {
        public UaRequest(string username, string serviceName, string methodName, string password)
        {
            Username = username;
            ServiceName = serviceName;
            MethodName = methodName;
            Password = password;
        }

        public UaRequest(string username, string serviceName, string methodName, string language, string subMethods)
        {
            Username = username;
            ServiceName = serviceName;
            MethodName = methodName;
        }

        public string Username { get; }
        public string ServiceName { get; }
        public string MethodName { get; }
        public string Password { get; }
        public string Language { get; }
        public string Submethods { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_REQUEST;
        public byte MessageId => (byte)Type;

        public virtual byte[] GetBytes()
        {
            var size = 1 + Username.GetStringSize() + ServiceName.GetAsciiStringSize() + MethodName.GetAsciiStringSize();
            if (MethodName == "password")
            {
                size += 1 + Password.GetStringSize();
            }

            if (MethodName == "keyboard-interactive")
            {
                size += Language.GetStringSize() + Submethods.GetStringSize();
            }

            var writer = new ByteWriter(size);
            writer.WriteByte(MessageId);
            writer.WriteString(Username);
            writer.WriteAsciiString(ServiceName);
            writer.WriteAsciiString(MethodName);
            if (MethodName == "password")
            {
                writer.WriteByte(0);
                writer.WriteString(Password);
            }

            if (MethodName == "keyboard-interactive")
            {
                writer.WriteString(Language);
                writer.WriteString(Submethods);
            }

            return writer.Bytes;
        }
    }
}
;