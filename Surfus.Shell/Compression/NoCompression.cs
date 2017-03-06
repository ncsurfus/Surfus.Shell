namespace Surfus.Shell.Compression
{
    /// <summary>
    /// This class implements no compression algorithm. The data is simply returned.
    /// </summary>
    internal class NoCompression : CompressionAlgorithm
    {
        /// <summary>
        /// Disposes the CompressionAlgorithm.
        /// </summary>
        public override void Dispose()
        {
        }

        /// <summary>
        /// Compresses the data.
        /// </summary>
        /// <param name="data">
        /// The data;
        /// </param>
        /// <returns>
        /// The compressed data.
        /// </returns>
        public override byte[] Compress(byte[] data)
        {
            return data;
        }

        /// <summary>
        /// Decompresses the data.
        /// </summary>
        /// <param name="data">
        /// The data.
        /// </param>
        /// <returns>
        /// The decompressed data.
        /// </returns>
        public override byte[] Decompress(byte[] data)
        {
            return data;
        }
    }
}
