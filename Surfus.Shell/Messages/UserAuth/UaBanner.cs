using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaBanner : IMessage
    {
        public UaBanner(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                Message = stream.ReadString();
                LanguageTag = stream.ReadString();
            }
        }

        public UaBanner(string message, string languageTag)
        {
            Message = message;
            LanguageTag = languageTag;
        }

        public string Message { get; }
        public string LanguageTag { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_BANNER;
        public byte MessageId => (byte)Type;

        public virtual byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);
                memoryStream.WriteString(Message);
                memoryStream.WriteString(LanguageTag);
                return memoryStream.ToArray();
            }
        }
    }
}
