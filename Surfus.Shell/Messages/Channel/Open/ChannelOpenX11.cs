﻿using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Open
{
    public class ChannelOpenX11 : ChannelOpen
    {
        public ChannelOpenX11(byte[] buffer) : base(buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                stream.Position = BaseMemoryStreamPosition;
                OriginatorAddress = stream.ReadString();
                OriginatorPort = stream.ReadUInt32();
            }
        }

        public ChannelOpenX11(string originatorAddress, uint originatorPort, uint senderChannel) : base("x11", senderChannel)
        {
            OriginatorAddress = originatorAddress;
            OriginatorPort = originatorPort;
        }

        public string OriginatorAddress { get; }
        public uint OriginatorPort { get; }

        public override byte[] GetBytes()
        {
            using (var memoryStream = GetMemoryStream())
            {
                memoryStream.WriteString(OriginatorAddress);
                memoryStream.WriteUInt(OriginatorPort);
                return memoryStream.ToArray();
            }
        }
    }
}
