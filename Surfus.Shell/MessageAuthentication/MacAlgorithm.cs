using System;

namespace Surfus.Shell.MessageAuthentication
{
    internal abstract class MacAlgorithm
    {
        public abstract int KeySize { get; protected set; }
        public abstract int OutputSize { get; }

        public static string[] Supported => new[] { "hmac-sha2-512", "hmac-sha2-256", "hmac-sha1-96", "hmac-sha1" };
        public abstract void Initialize(byte[] key);

        public abstract byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket);
        public abstract bool VerifyMac(byte[] expectedMac, uint sequenceNumber, SshPacket sshPacket);

        public static MacAlgorithm Create(string name)
        {
            switch (name)
            {
                case "hmac-sha1":
                    return new HmacSha1MacAlgorithm();
                case "hmac-sha1-96":
                    return new HmacSha1B96MacAlgorithm();
                case "hmac-sha2-256":
                    return new HmacSha256MacAlgorithm();
                case "hmac-sha2-512":
                    return new HmacSha512MacAlgorithm();
            }

            throw new Exception("Message authentication algorithm not supported");
        }
    }
}
