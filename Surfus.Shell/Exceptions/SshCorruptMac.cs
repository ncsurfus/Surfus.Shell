namespace Surfus.Shell.Exceptions
{
    public class SshCorruptMac : SshException
    {
        internal SshCorruptMac(uint packetSequence) : base("Corrupted message authentication code from server.")
        {
            PacketSequence = packetSequence;
        }

        public uint PacketSequence { get; }
    }
}
