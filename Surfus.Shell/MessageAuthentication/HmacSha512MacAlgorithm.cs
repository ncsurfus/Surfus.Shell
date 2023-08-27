using System.Security.Cryptography;
using System;

namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class HmacSha512MacAlgorithm : MacAlgorithm
    {
        private HMACSHA512 _macProvider;

        public override int KeySize { get; protected set; } = 64;
        public override int OutputSize => 64;

        public override void Initialize(byte[] key)
        {
            if (key.Length != KeySize)
            {
                Array.Resize(ref key, KeySize);
            }

            _macProvider = new HMACSHA512 { Key = key };
            _macProvider.Initialize();
        }

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            return _macProvider.ComputeHash(sshPacket.Buffer, 0, sshPacket.Length + 4);
        }

        public override bool VerifyMac(uint sequenceNumber, SshPacket sshPacket)
        {
            var computedMac = ComputeHash(sequenceNumber, sshPacket);
            for (int i = 0; i != OutputSize; i++)
            {
                if (sshPacket.Buffer[sshPacket.Length + 4 + i] != computedMac[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
