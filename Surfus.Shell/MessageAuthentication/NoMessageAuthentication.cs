namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class NoMessageAuthentication : MacAlgorithm
    {
        public override int KeySize { get; protected set; } = 0;
        public override int OutputSize { get; } = 0;

        public override void Initialize(byte[] key)
        {
           
        }

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            return new byte[] { };
        }

        public override bool VerifyMac(byte[] expectedMac, uint sequenceNumber, SshPacket sshPacket)
        {
            return expectedMac.Length != 0;
        }
    }
}
