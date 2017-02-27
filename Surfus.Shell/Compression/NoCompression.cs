// --------------------------------------------------------------------------------------------------------------------
// <copyright file="NoCompression.cs" company="Nathan Surfus">
//   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
//   THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//   IN THE SOFTWARE.
// </copyright>
// <summary>
//   This class implements no compression algorithm. The data is simply returned.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

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
