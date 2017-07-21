using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class HmacSha256MacAlgorithm : MacAlgorithm
    {
        private HMACSHA256 _macProvider;

        public override int KeySize { get; protected set; } = 32;
        public override int OutputSize => 32;

        public override void Initialize(byte[] key)
        {
            _macProvider = new HMACSHA256
            {
                Key = key.Take(32).ToArray()
            };
            _macProvider.Initialize();
        }

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            using (var memoryStream = new MemoryStream())
            {
                memoryStream.WriteUInt(sequenceNumber);
                memoryStream.Write(sshPacket.Buffer);
                return _macProvider.ComputeHash(memoryStream.ToArray());
            }
        }

        public override bool VerifyMac(byte[] expectedMac, uint sequenceNumber, SshPacket sshPacket)
        {
            return expectedMac.SequenceEqual(ComputeHash(sequenceNumber, sshPacket));
        }
    }
}
