using System.IO;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Messages.Channel.Open
{
    internal class ChannelOpenForwardedTcpIp : ChannelOpen
    {
        public ChannelOpenForwardedTcpIp(SshPacket packet) : base(packet, "forwarded-tcpip")
        {
            AddressConnected = packet.Reader.ReadString();
            PortConnected = packet.Reader.ReadUInt32();
            OriginatorAddress = packet.Reader.ReadString();
            OriginatorPort = packet.Reader.ReadUInt32();
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
            var writer = GetByteWriter(GetBaseSize() + AddressConnected.GetStringSize() + 4 + OriginatorAddress.GetStringSize() + 4);
            writer.WriteString(AddressConnected);
            writer.WriteUint(PortConnected);
            writer.WriteString(OriginatorAddress);
            writer.WriteUint(OriginatorPort);
            return writer.Bytes;
        }
    }
}
