using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages
{
    public class Ignore : IClientMessage
    {
        public Ignore(SshPacket packet)
        {
            Data = packet.Reader.ReadString();
        }

        public Ignore(string data)
        {
            Data = data;
        }

        public string Data { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_IGNORE;
        public byte MessageId => (byte)Type;

        public byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteString(Data);
                return memoryStream.ToArray();
            }
        }
    }
}
