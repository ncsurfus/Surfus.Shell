﻿using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Requests
{
    public class ChannelRequestSubsystem : ChannelRequest
    {
        public ChannelRequestSubsystem(SshPacket packet, uint recipientChannel) : base(packet, "subsystem", recipientChannel)
        {
            Subsystem = packet.Reader.ReadString();
        }

        public ChannelRequestSubsystem(uint recipientChannel, bool wantReply, string subsystem) : base(recipientChannel, "subsysem", wantReply)
        {
            Subsystem = subsystem;
        }

        public string Subsystem { get; }

        public override byte[] GetBytes()
        {
            using (var stream = GetMemoryStream())
            {
                stream.WriteString(Subsystem);
                return stream.ToArray();
            }
        }
    }
}
