namespace Surfus.Shell.Extensions
{
    public static class EndianExtensions
    {
        internal static byte[] GetBigEndianBytes(this uint value)
        {
            return new [] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)(value & 0xFF) };
        }
    }
}
