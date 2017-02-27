using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaInfoRequest : IMessage
    {
        public UaInfoRequest(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var awaitedByte = stream.ReadByte();
                if (awaitedByte != MessageId)
                {
                    throw new Exception($"Expected Type: {Type}");
                }

                Name = stream.ReadString();
                Instruction = stream.ReadString();
                Language = stream.ReadString();
                PromptNumber = stream.ReadUInt32();
                Prompt = new string[PromptNumber];
                Echo = new bool[PromptNumber];

                for (int i = 0; i != PromptNumber; i++)
                {
                    Prompt[i] = stream.ReadString();
                    Echo[i] = stream.ReadBoolean();
                }
            }
        }

        public UaInfoRequest(string name, string instruction, string language, uint numberPrompts, string[] prompt, bool[] echo)
        {
            Name = name;
            Instruction = instruction;
            Language = language;
            PromptNumber = numberPrompts;
            Prompt = prompt;
            Echo = echo;
        }

        public string Name { get; }
        public string Instruction { get; }
        public string Language { get; }
        public uint PromptNumber { get; }
        public string[] Prompt { get; }
        public bool[] Echo { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_INFO_REQUEST;
        public byte MessageId => (byte)Type;

        public virtual byte[] GetBytes()
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteByte(MessageId);

                memoryStream.WriteString(Name);
                memoryStream.WriteString(Instruction);
                memoryStream.WriteString(Language);
                memoryStream.WriteUInt(PromptNumber);
                
                for (int i = 0; i != PromptNumber; i++)
                {
                    memoryStream.WriteString(Prompt[i]);
                    memoryStream.WriteByte(Echo[i] ? (byte)1 : (byte)0);
                }

                return memoryStream.ToArray();
            }
        }
    }
}
