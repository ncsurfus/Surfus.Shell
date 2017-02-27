using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages
{
    public class Ignore : IMessage
    {
        public Ignore(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                Data = stream.ReadString();
            }
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
