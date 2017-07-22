using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages
{
    public class ServiceRequest : IClientMessage
    {
        public ServiceRequest(SshPacket packet)
        {
            ServiceName = packet.Reader.ReadString();
        }

        public ServiceRequest(string serviceName)
        {
            ServiceName = serviceName;
        }

        public string ServiceName { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_SERVICE_REQUEST;
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
