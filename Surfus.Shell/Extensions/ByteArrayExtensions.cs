namespace Surfus.Shell.Extensions
{
    public static class ByteArrayExtensions
    {
        public static uint FromBigEndianToUint(this byte[] byteArray, int index = 0)
        {
            return (uint)(byteArray[index + 0] << 24 | byteArray[index + 1] << 16 | byteArray[index + 2] << 8 | byteArray[index + 3]);
        }
    }
}
