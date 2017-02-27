using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaRequest : IMessage
    {
        public UaRequest(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                Username = stream.ReadString();
                ServiceName = stream.ReadAsciiString();
                MethodName = stream.ReadAsciiString();
                if (MethodName == "password")
                {
                    Password = Password;
                }

                if (MethodName == "keyboard-interactive")
                {
                    Language = stream.ReadString();
                    Submethods = stream.ReadString();
                }
            }
        }

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
            Language = language;
            Submethods = subMethods;
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
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteString(Username);
                memoryStream.WriteAsciiString(ServiceName);
                memoryStream.WriteAsciiString(MethodName);
                if (MethodName == "password")
                {
                    memoryStream.WriteByte(0);
                    memoryStream.WriteString(Password);
                }

                if (MethodName == "keyboard-interactive")
                {
                    memoryStream.WriteString(Language ?? "");
                    memoryStream.WriteString(Submethods ?? "");
                }

                return memoryStream.ToArray();
            }
        }
    }
}
