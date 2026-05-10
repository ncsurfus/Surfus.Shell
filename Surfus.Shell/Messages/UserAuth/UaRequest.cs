using System;

namespace Surfus.Shell.Messages.UserAuth
{
    internal record UaRequest : IClientMessage
    {
        public UaRequest(string username, string serviceName, string methodName, string password)
        {
            Username = username;
            ServiceName = serviceName;
            MethodName = methodName;
            Password = password;
        }

        public UaRequest(string username, string serviceName, string methodName, string? language, string? subMethods)
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
        public string? Password { get; }
        public string? Language { get; }
        public string? Submethods { get; }
        public bool HasSignature { get; }
        public string? PublicKeyAlgorithm { get; }
        public ReadOnlyMemory<byte> PublicKeyBlob { get; }
        public ReadOnlyMemory<byte> Signature { get; }

        public UaRequest(
            string username,
            string serviceName,
            string publicKeyAlgorithm,
            ReadOnlyMemory<byte> publicKeyBlob,
            ReadOnlyMemory<byte> signature
        )
        {
            Username = username;
            ServiceName = serviceName;
            MethodName = "publickey";
            HasSignature = !signature.IsEmpty;
            PublicKeyAlgorithm = publicKeyAlgorithm;
            PublicKeyBlob = publicKeyBlob;
            Signature = signature;
        }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_REQUEST;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var size = Username.GetStringSize() + ServiceName.GetAsciiStringSize() + MethodName.GetAsciiStringSize();
            if (MethodName == "password")
            {
                size += 1 + Password!.GetStringSize();
            }
            else if (MethodName == "keyboard-interactive")
            {
                size += Language!.GetStringSize() + Submethods!.GetStringSize();
            }
            else if (MethodName == "publickey")
            {
                size += 1 + PublicKeyAlgorithm!.GetAsciiStringSize() + PublicKeyBlob.GetBinaryStringSize();
                if (HasSignature)
                {
                    size += Signature.GetBinaryStringSize();
                }
            }

            var writer = new ByteWriter(Type, size);
            writer.WriteString(Username);
            writer.WriteAsciiString(ServiceName);
            writer.WriteAsciiString(MethodName);
            if (MethodName == "password")
            {
                writer.WriteByte(0);
                writer.WriteString(Password!);
            }
            else if (MethodName == "keyboard-interactive")
            {
                writer.WriteString(Language!);
                writer.WriteString(Submethods!);
            }
            else if (MethodName == "publickey")
            {
                writer.WriteByte(HasSignature ? (byte)1 : (byte)0);
                writer.WriteAsciiString(PublicKeyAlgorithm!);
                writer.WriteBinaryString(PublicKeyBlob);
                if (HasSignature)
                {
                    writer.WriteBinaryString(Signature);
                }
            }

            return writer;
        }
    }
};
