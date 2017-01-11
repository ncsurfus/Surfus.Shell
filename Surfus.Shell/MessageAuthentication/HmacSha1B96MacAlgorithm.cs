using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class HmacSha1B96MacAlgorithm : MacAlgorithm
    {
        private HMACSHA1 _macProvider;

        public override int KeySize { get; protected set; } = 20;
        public override int OutputSize => 12;

        public override void Initialize(byte[] key)
        {
			_macProvider = new HMACSHA1();
			_macProvider.Key = key.Take(20).ToArray();
			_macProvider.Initialize();
        }

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteUInt(sequenceNumber);
                memoryStream.Write(sshPacket.Raw);
                return _macProvider.ComputeHash(memoryStream.ToArray()).Take(12).ToArray();
            }
        }

        public override bool VerifyMac(byte[] expectedMac, uint sequenceNumber, SshPacket sshPacket)
        {
            return expectedMac.SequenceEqual(ComputeHash(sequenceNumber, sshPacket));
        }
    }
}
