namespace Surfus.Shell.Common
{
    public struct PacketSegment
    {
        public readonly byte[] Array;
        public readonly int Offset;
        public readonly int Count;

        public PacketSegment(byte[] array, int offset, int count)
        {
            Array = array;
            Offset = offset;
            Count = count;
        }
    }
}
