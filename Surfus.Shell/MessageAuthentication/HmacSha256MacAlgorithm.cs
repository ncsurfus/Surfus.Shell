using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;
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

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            ByteWriter.WriteUint(sshPacket.Buffer, 0, sequenceNumber);
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
