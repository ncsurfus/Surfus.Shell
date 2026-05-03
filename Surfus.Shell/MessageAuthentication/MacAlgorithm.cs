using System;

namespace Surfus.Shell.MessageAuthentication
{
    public abstract class MacAlgorithm
    {
        public abstract int KeySize { get; protected set; }
        public abstract int OutputSize { get; }
        public abstract void Initialize(byte[] key);

        public abstract byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket);
        public abstract bool VerifyMac(uint sequenceNumber, SshPacket sshPacket);
    }
}
