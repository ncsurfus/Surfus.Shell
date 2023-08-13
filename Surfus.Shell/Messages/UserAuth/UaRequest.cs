using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Agent;

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


        public UaRequest(string username, string serviceName, SshAgentKey key, ReadOnlyMemory<byte> signature)
        {
            Username = username;
            ServiceName = serviceName;
            Key = key;
            MethodName = "publickey";
            Signature = signature;
        }

        public string Username { get; }
        public string ServiceName { get; }
        public string MethodName { get; }
        public string Password { get; }
        public string Language { get; }
        public string Submethods { get; }

        public SshAgentKey Key { get; }
        public ReadOnlyMemory<byte> Signature { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_REQUEST;
        public byte MessageId => (byte)Type;

        public static async Task<ReadOnlyMemory<byte>> CalculateSignatureAsync(
            string username,
            string serviceName,
            SshAgentKey key,
            byte[] sessionIdentifier,
            CancellationToken cancellationToken)
        {
            var methodName = "publickey";
            var size = sessionIdentifier.GetBinaryStringSize() +
                1 +
                username.GetStringSize() + 
                serviceName.GetAsciiStringSize() + 
                methodName.GetAsciiStringSize() +
                1 +
                key.KeyType.GetAsciiStringSize() +
                key.PublicKey.Span.GetBinaryStringSize();

            var writer = new ByteWriter(size);
            writer.WriteBinaryString(sessionIdentifier);
            writer.WriteByte((byte)MessageType.SSH_MSG_USERAUTH_REQUEST);
            writer.WriteString(username);
            writer.WriteAsciiString(serviceName);
            writer.WriteAsciiString(methodName);
            writer.WriteByte(1);
            writer.WriteAsciiString(key.KeyType);
            writer.WriteBinaryString(key.PublicKey.Span);
            var bytes = writer.Bytes.AsMemory(writer.DataIndex, writer.DataLength);
            var signature = await key.SignPrivateKey(bytes, cancellationToken);
            return signature;
        }

        public ByteWriter GetByteWriter()
        {
            var size = Username.GetStringSize() + ServiceName.GetAsciiStringSize() + MethodName.GetAsciiStringSize();
            if (MethodName == "password")
            {
                size += 1 + Password.GetStringSize();
            }

            if (MethodName == "keyboard-interactive")
            {
                size += Language.GetStringSize() + Submethods.GetStringSize();
            }

            if (MethodName == "publickey")
            {
                size += 1 +
                    Key.KeyType.GetAsciiStringSize() +
                    Key.PublicKey.Span.GetBinaryStringSize() + 
                    Signature.Span.GetBinaryStringSize();
            }

            var writer = new ByteWriter(Type, size);
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

            if (MethodName == "publickey")
            {
                writer.WriteByte(1);
                writer.WriteAsciiString(Key.KeyType);
                writer.WriteBinaryString(Key.PublicKey.Span);
                writer.WriteBinaryString(Signature.Span);
            }

            return writer;
        }
    }
}
;