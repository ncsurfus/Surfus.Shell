using System;
using System.Security.Cryptography;

namespace Surfus.Shell.MessageAuthentication
{
    public sealed class HmacSha1MacAlgorithm : MacAlgorithm
    {
        private HMACSHA1 _macProvider = null!;

        public override int KeySize => 20;
        public override int OutputSize => 20;

        public override void Initialize(byte[] key)
        {
            if (key.Length != KeySize)
            {
                Array.Resize(ref key, KeySize);
            }

            _macProvider = new HMACSHA1 { Key = key };
            _macProvider.Initialize();
        }

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            return _macProvider.ComputeHash(sshPacket.Buffer, 0, sshPacket.Length + 4);
        }

        public override bool VerifyMac(uint sequenceNumber, SshPacket sshPacket)
        {
            var computedMac = ComputeHash(sequenceNumber, sshPacket);
            return CryptographicOperations.FixedTimeEquals(
                computedMac.AsSpan(0, OutputSize),
                sshPacket.Buffer.AsSpan(sshPacket.Length + 4, OutputSize)
            );
        }
    }
}
