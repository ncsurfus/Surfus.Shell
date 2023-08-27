using System;
using Surfus.Shell.Exceptions;

namespace Surfus.Shell.Compression
{
    /// <summary>
    /// Servers as the base for all compression algorithms.
    /// </summary>
    internal abstract class CompressionAlgorithm : IDisposable
    {
        /// <summary>
        /// Supported compression algorithms.
        /// </summary>
        internal static string[] Supported => new[] { "none" };

        /// <summary>
        /// Creates the specified compression algorithm.
        /// </summary>
        /// <param name="name">
        /// The name of the compression algorithm.
        /// </param>
        internal static CompressionAlgorithm Create(string name)
        {
            if (name == "none")
            {
                return new NoCompression();
            }

            throw new SshException("Compression algorithm not supported");
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
        internal abstract byte[] Compress(byte[] data);

        /// <summary>
        /// Decompresses the data.
        /// </summary>
        /// <param name="data">
        /// The data.
        /// </param>
        /// <returns>
        /// The decompressed data.
        /// </returns>
        internal abstract byte[] Decompress(byte[] data);

        /// <summary>
        /// Disposes the compression algorithm.
        /// </summary>
        public abstract void Dispose();
    }
}
