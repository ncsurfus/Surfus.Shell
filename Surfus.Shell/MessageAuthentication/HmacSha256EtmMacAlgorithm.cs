using System;
using System.Security.Cryptography;

namespace Surfus.Shell.MessageAuthentication
{
    public sealed class HmacSha256EtmMacAlgorithm : MacAlgorithm
    {
        private HMACSHA256 _macProvider = null!;

        public override int KeySize => 32;
        public override int OutputSize => 32;
        public override bool IsEtm => true;

        public override void Initialize(byte[] key)
        {
            if (key.Length != KeySize)
            {
                Array.Resize(ref key, KeySize);
            }
            _macProvider = new HMACSHA256 { Key = key };
            _macProvider.Initialize();
        }

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            // ETM: MAC covers sequence_number (4 bytes) + entire ciphertext (packet_length + encrypted body)
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
