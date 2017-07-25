using System.Security.Cryptography;
using System;

namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class HmacSha1MacAlgorithm : MacAlgorithm
    {
        private HMACSHA1 _macProvider;

        public override int KeySize { get; protected set; } = 20;
        public override int OutputSize => 20;

        public override void Initialize(byte[] key)
        {
            if (key.Length != KeySize)
            {
                Array.Resize(ref key, KeySize);
            }

            _macProvider = new HMACSHA1
            {
                Key = key
            };
            _macProvider.Initialize();
        }

        public override byte[] ComputeHash(SshPacket sshPacket)
        {
            return _macProvider.ComputeHash(sshPacket.MacVerificationBytes.Array, sshPacket.MacVerificationBytes.Offset, sshPacket.MacVerificationBytes.Count);
        }

        public override bool VerifyMac(SshPacket sshPacket)
        {
            var computedMac = ComputeHash(sshPacket);
            for (int i = 0; i != OutputSize; i++)
            {
                if (sshPacket.ServerMacResult.Array[sshPacket.ServerMacResult.Offset + i] != computedMac[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
