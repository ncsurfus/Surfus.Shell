using System.Security.Cryptography;
using System;

namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class HmacSha256MacAlgorithm : MacAlgorithm
    {
        private HMACSHA256 _macProvider;

        public override int KeySize { get; protected set; } = 32;
        public override int OutputSize => 32;

        public override void Initialize(byte[] key)
        {
            if (key.Length != KeySize)
            {
                Array.Resize(ref key, KeySize);
            }
            _macProvider = new HMACSHA256
            {
                Key = key
            };
            _macProvider.Initialize();
        }

        public override byte[] ComputeHash(SshPacket sshPacket)
        {
            return _macProvider.ComputeHash(sshPacket.MacVerificationBytes.Array, sshPacket.MacVerificationBytes.Offset, sshPacket.MacVerificationBytes.Count);
        }

        public override byte[] ComputeHash(ArraySegment<byte> data)
        {
            return _macProvider.ComputeHash(data.Array, data.Offset, data.Count);
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
