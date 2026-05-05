using System;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Compression
{
    /// <summary>
    /// Servers as the base for all compression algorithms.
    /// </summary>
    public abstract class CompressionAlgorithm : IDisposable
    {
        /// <summary>
        /// Compresses the data.
        /// </summary>
        /// <param name="data">
        /// The data;
        /// </param>
        /// <returns>
        /// The compressed data.
        /// </returns>
        internal abstract byte[] Compress(ReadOnlyMemory<byte> data);

        /// <summary>
        /// Decompresses the data.
        /// </summary>
        /// <param name="data">
        /// The data.
        /// </param>
        /// <returns>
        /// The decompressed data.
        /// </returns>
        internal abstract byte[] Decompress(ReadOnlyMemory<byte> data);

        /// <summary>
        /// Disposes the compression algorithm.
        /// </summary>
        public abstract void Dispose();
    }
}
