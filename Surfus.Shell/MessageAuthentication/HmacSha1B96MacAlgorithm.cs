using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;
using System;

namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class HmacSha1B96MacAlgorithm : MacAlgorithm
    {
        private HMACSHA1 _macProvider;

        public override int KeySize { get; protected set; } = 20;
        public override int OutputSize => 12;

        public override void Initialize(byte[] key)
        {
            if(key.Length != KeySize)
            {
                Array.Resize(ref key, KeySize);
            }

            _macProvider = new HMACSHA1
            {
                Key = key
            };
            _macProvider.Initialize();
        }

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            var writer = new ByteWriter(4 + sshPacket.Buffer.Length);
            writer.WriteUint(sequenceNumber);
            writer.WriteByteBlob(sshPacket.Buffer);
            return _macProvider.ComputeHash(writer.Bytes);
        }

        public override bool VerifyMac(byte[] expectedMac, uint sequenceNumber, SshPacket sshPacket)
        {
            var computedMac = ComputeHash(sequenceNumber, sshPacket);
            if (expectedMac.Length != OutputSize || computedMac.Length < OutputSize)
            {
                return false;
            }
            for (int i = 0; i != OutputSize; i++)
            {
                if (expectedMac[i] != computedMac[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
