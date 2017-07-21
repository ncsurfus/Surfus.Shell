using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages
{
    public class ServiceAccept : IMessage
    {
        public ServiceAccept(SshPacket packet)
        {
            ServiceName = packet.Reader.ReadString();
        }

        public ServiceAccept(string serviceName)
        {
            ServiceName = serviceName;
        }

        public string ServiceName { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_SERVICE_ACCEPT;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteString(ServiceName);
                return memoryStream.ToArray();
            }
        }
    }
}
