using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;
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

            _macProvider = new HMACSHA512
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

        public override bool VerifyMac(byte[] expectedMac, uint sequenceNumber, SshPacket sshPacket)
        {
            var computedMac = ComputeHash(sequenceNumber, sshPacket);
            if(expectedMac != computedMac)
            {
                return false;
            }
            for (int i = 0; i != expectedMac.Length; i++)
            {
                if(expectedMac[i] != computedMac[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
