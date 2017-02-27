using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Open
{
    public class ChannelOpenDirectTcpIp : ChannelOpen
    {
        public ChannelOpenDirectTcpIp(byte[] buffer) : base(buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                stream.Position = BaseMemoryStreamPosition;
                Host = stream.ReadString();
                Port = stream.ReadUInt32();
                OriginatorAddress = stream.ReadString();
                OriginatorPort = stream.ReadUInt32();
            }
        }

        public ChannelOpenDirectTcpIp(string host, uint port, string originatorAddress, uint originatorPort, uint senderChannel) : base("direct-tcpip", senderChannel)
        {
            Host = host;
            Port = port;
            OriginatorAddress = originatorAddress;
            OriginatorPort = originatorPort;
        }

        public string Host { get; }
        public uint Port { get; }
        public string OriginatorAddress { get; }
        public uint OriginatorPort { get; }

        public override byte[] GetBytes()
        {
            using (var memoryStream = GetMemoryStream())
            {
                memoryStream.WriteString(Host);
                memoryStream.WriteUInt(Port);
                memoryStream.WriteString(OriginatorAddress);
                memoryStream.WriteUInt(OriginatorPort);
                return memoryStream.ToArray();
            }
        }
    }
}
