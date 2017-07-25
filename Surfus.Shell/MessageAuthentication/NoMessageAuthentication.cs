namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class NoMessageAuthentication : MacAlgorithm
    {
        public override int KeySize { get; protected set; } = 0;
        public override int OutputSize { get; } = 0;

        public override void Initialize(byte[] key)
        {
           
        }

        public override byte[] ComputeHash(SshPacket sshPacket)
        {
            return null;
        }

        public override bool VerifyMac(SshPacket sshPacket)
        {
            return true;
        }
    }
}
