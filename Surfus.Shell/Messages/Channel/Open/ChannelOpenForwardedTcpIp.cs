using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Open
{
    public class ChannelOpenForwardedTcpIp : ChannelOpen
    {
        public ChannelOpenForwardedTcpIp(byte[] buffer) : base(buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                stream.Position = BaseMemoryStreamPosition;
                AddressConnected = stream.ReadString();
                PortConnected = stream.ReadUInt32();
                OriginatorAddress = stream.ReadString();
                OriginatorPort = stream.ReadUInt32();
            }
        }

        public ChannelOpenForwardedTcpIp(string addressConnected, uint portConnected, string originatorAddress, uint originatorPort, uint senderChannel) : base("forwarded-tcpip", senderChannel)
        {
            AddressConnected = addressConnected;
            PortConnected = portConnected;
            OriginatorAddress = originatorAddress;
            OriginatorPort = originatorPort;
        }

        public string AddressConnected { get; }
        public uint PortConnected { get; }
        public string OriginatorAddress { get; }
        public uint OriginatorPort { get; }

        public override byte[] GetBytes()
        {
            using (var memoryStream = GetMemoryStream())
            {
                memoryStream.WriteString(AddressConnected);
                memoryStream.WriteUInt(PortConnected);
                memoryStream.WriteString(OriginatorAddress);
                memoryStream.WriteUInt(OriginatorPort);
                return memoryStream.ToArray();
            }
        }
    }
}
