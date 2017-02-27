// --------------------------------------------------------------------------------------------------------------------
// <copyright file="KexInitExchangeResult.cs" company="Nathan Surfus">
//   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
//   THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//   IN THE SOFTWARE.
// </copyright>
// <summary>
//   Compares the client and server KexInit messages and selects the appropriate ciphers.
//   RFC: https://tools.ietf.org/html/rfc4253
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System.Linq;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.KeyExchange;

namespace Surfus.Shell.KeyExchange
{
    /// <summary>
    /// Compares the client and server KexInit messages and selects the appropriate ciphers.
    /// </summary>
    internal class KexInitExchangeResult
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KexInitExchangeResult"/> class.
        /// </summary>
        /// <param name="client">
        /// The client KexInit packet.
        /// </param>
        /// <param name="server">
        /// The server KexInit packet.
        /// </param>
        public KexInitExchangeResult(KexInit client, KexInit server)
        {
            Client = client;
            Server = server;
            KeyExchangeAlgorithm = SelectAlgorithm(Client.KexAlgorithms, Server.KexAlgorithms);
            ServerHostKeyAlgorithm = SelectAlgorithm(Client.ServerHostKeyAlgorithms, Server.ServerHostKeyAlgorithms);
            EncryptionClientToServer = SelectAlgorithm(Client.EncryptionClientToServer, Server.EncryptionClientToServer);
            EncryptionServerToClient = SelectAlgorithm(Client.EncryptionServerToClient, Server.EncryptionServerToClient);
            MessageAuthenticationClientToServer = SelectAlgorithm(Client.MacClientToServer, Server.MacClientToServer);
            MessageAuthenticationServerToClient = SelectAlgorithm(Client.MacServerToClient, Server.MacServerToClient);
            CompressionClientToServer = SelectAlgorithm(Client.CompressionClientToServer, Server.CompressionClientToServer);
            CompressionServerToClient = SelectAlgorithm(Client.CompressionServerToClient, Server.CompressionServerToClient);
        }

        /// <summary>
        /// Gets the client KexInit message.
        /// </summary>
        public KexInit Client { get; }

        /// <summary>
        /// Gets the server KexInit message.
        /// </summary>
        public KexInit Server { get; }

        /// <summary>
        /// Gets the key exchange algorithm.
        /// </summary>
        public string KeyExchangeAlgorithm { get; }

        /// <summary>
        /// Gets the server host key algorithm.
        /// </summary>
        public string ServerHostKeyAlgorithm { get; }

        /// <summary>
        /// Gets the client to server encryption cipher.
        /// </summary>
        public string EncryptionClientToServer { get; }

        /// <summary>
        /// Gets the server to client encryption cipher.
        /// </summary>
        public string EncryptionServerToClient { get; }

        /// <summary>
        /// Gets the client to server compression algorithm.
        /// </summary>
        public string CompressionClientToServer { get; }

        /// <summary>
        /// Gets the server to client compression algorithm.
        /// </summary>
        public string CompressionServerToClient { get; }

        /// <summary>
        /// Gets the client to server message authentication algorithm.
        /// </summary>
        public string MessageAuthenticationClientToServer { get; }

        /// <summary>
        /// Gets the server to client message authentication algorithm.
        /// </summary>
        public string MessageAuthenticationServerToClient { get; }

        /// <summary>
        /// Selects the appropriate cipher from the client and server NameLists.
        /// </summary>
        /// <param name="client">
        /// The client NameList.
        /// </param>
        /// <param name="server">
        /// The server NameList.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        /// <exception cref="SshException">
        /// Throws an SshException if no common cipher is found between the client and server.
        /// </exception>
        private static string SelectAlgorithm(NameList client, NameList server)
        {
            var algorithm = client.Names.FirstOrDefault(clientAlgorithm => server.Names.Any(x => x == clientAlgorithm));

            if (algorithm == null)
            {
                throw new SshException("No common cipher was found. Key exchange failed.");
            }

            return algorithm;
        }
    }
}
