using System;

namespace Surfus.Shell.Compression
{
    /// <summary>
    /// This class implements no compression algorithm. The data is simply returned.
    /// </summary>
    public class NoCompression : CompressionAlgorithm
    {
        /// <summary>
        /// Disposes the CompressionAlgorithm.
        /// </summary>
        public override void Dispose() { }

        /// <summary>
        /// Compresses the data.
        /// </summary>
        /// <param name="data">
        /// The data;
        /// </param>
        /// <returns>
        /// The compressed data.
        /// </returns>
        internal override byte[] Compress(ReadOnlyMemory<byte> data)
        {
            return data.ToArray();
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
        internal override byte[] Decompress(ReadOnlyMemory<byte> data)
        {
            return data.ToArray();
        }
    }
}
