// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CompressAlgorithm.cs" company="Nathan Surfus">
//   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
//   THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//   IN THE SOFTWARE.
// </copyright>
// <summary>
//   Provides the fundamentals all compression algorithms must implement.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

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
        public static string[] Supported => new[] { "none" };

        /// <summary>
        /// Creates the specified compression algorithm.
        /// </summary>
        /// <param name="name">
        /// The name of the compression algorithm.
        /// </param>
        public static CompressionAlgorithm Create(string name)
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
        public abstract byte[] Compress(byte[] data);

        /// <summary>
        /// Decompresses the data.
        /// </summary>
        /// <param name="data">
        /// The data.
        /// </param>
        /// <returns>
        /// The decompressed data.
        /// </returns>
        public abstract byte[] Decompress(byte[] data);

        /// <summary>
        /// Disposes the compression algorithm.
        /// </summary>
        public abstract void Dispose();
    }
}