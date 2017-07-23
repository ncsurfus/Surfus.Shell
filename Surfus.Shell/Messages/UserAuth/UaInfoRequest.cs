using System;
using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.UserAuth
{
    public class UaInfoRequest : IMessage
    {
        public UaInfoRequest(SshPacket packet)
        {
            Name = packet.Reader.ReadString();
            Instruction = packet.Reader.ReadString();
            Language = packet.Reader.ReadString();
            PromptNumber = packet.Reader.ReadUInt32();
            Prompt = new string[PromptNumber];
            Echo = new bool[PromptNumber];
            for (var i = 0; i != PromptNumber; i++)
            {
                Prompt[i] = packet.Reader.ReadString();
                Echo[i] = packet.Reader.ReadBoolean();
            }
        }
        public string Name { get; }
        public string Instruction { get; }
        public string Language { get; }
        public uint PromptNumber { get; }
        public string[] Prompt { get; }
        public bool[] Echo { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_USERAUTH_INFO_REQUEST;
        public byte MessageId => (byte)Type;
    }
}
