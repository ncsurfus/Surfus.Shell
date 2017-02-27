// --------------------------------------------------------------------------------------------------------------------
// <copyright file="MessageEvent.cs" company="N/A">
//   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
//   THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//   IN THE SOFTWARE.
// </copyright>
// <summary>
//   Holds the buffer containing the message and provides support to cast the message into the appropriate IMessage.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using Surfus.Shell.Messages.Channel;
using Surfus.Shell.Messages.KeyExchange;
using Surfus.Shell.Messages.UserAuth;

namespace Surfus.Shell.Messages
{
    /// <summary>
    /// Holds the buffer containing the message and provides support to cast the message into the appropriate IMessage.
    /// </summary>
    internal class MessageEvent
    {
        /// <summary>
        /// Caches the message for property Message.
        /// </summary>
        private IMessage _message;

        /// <summary>
        /// Initializes a new instance of the <see cref="MessageEvent"/> class.
        /// </summary>
        /// <param name="buffer">
        /// The buffer containing the data for the message.
        /// </param>
        public MessageEvent(byte[] buffer)
        {
            Buffer = buffer;
            Type = (MessageType)buffer[0];
            TypeId = buffer[0];
        }

        /// <summary>
        /// Gets the raw buffer of the message.
        /// </summary>
        public byte[] Buffer { get; }

        /// <summary>
        /// Gets the message type code.
        /// </summary>
        public int TypeId { get; }

        /// <summary>
        /// Gets the message type.
        /// </summary>
        public MessageType Type { get; }

        /// <summary>
        /// Gets the IMessage from the buffer.
        /// </summary>
        public IMessage Message
        {
            get
            {
                if (_message != null)
                {
                    return _message;
                }

                // ReSharper disable once SwitchStatementMissingSomeCases
                switch (Type)
                {
                    case MessageType.SSH_MSG_KEXINIT:
                        return _message = new KexInit(Buffer);
                   // case MessageType.SSH_MSG_KEX_DH_GEX_INIT:
                     //   return this.message = new DhInit(this.Buffer);
                  //  case MessageType.SSH_MSG_KEX_DH_GEX_REPLY:
                        //return this.message = new DhReply(this.Buffer);
                    case MessageType.SSH_MSG_NEWKEYS:
                        return _message = new NewKeys(Buffer);
                    case MessageType.SSH_MSG_IGNORE:
                        return _message = new Ignore(Buffer);
                    case MessageType.SSH_MSG_UNIMPLEMENTED:
                        return _message = new Unimplemented(Buffer);
                    case MessageType.SSH_MSG_DISCONNECT:
                        return _message = new Disconnect(Buffer);
                    case MessageType.SSH_MSG_SERVICE_ACCEPT:
                        return _message = new ServiceAccept(Buffer);
                    case MessageType.SSH_MSG_SERVICE_REQUEST:
                        return _message = new ServiceRequest(Buffer);
                    case MessageType.SSH_MSG_USERAUTH_REQUEST:
                        return _message = new UaRequest(Buffer);
                    case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                        return _message = new UaInfoRequest(Buffer);
                    case MessageType.SSH_MSG_USERAUTH_INFO_RESPONSE:
                        return _message = new UaInfoResponse(Buffer);
                    case MessageType.SSH_MSG_USERAUTH_FAILURE:
                        return _message = new UaFailure(Buffer);
                    case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                        return _message = new UaSuccess(Buffer);
                    case MessageType.SSH_MSG_USERAUTH_BANNER:
                        return _message = new UaBanner(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_OPEN:
                        return _message = ChannelOpen.FromBuffer(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_CLOSE:
                        return _message = new ChannelClose(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_EOF:
                        return _message = new ChannelEof(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                        return _message = new ChannelOpenConfirmation(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE:
                        return _message = new ChannelOpenFailure(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_REQUEST:
                        return _message = ChannelRequest.FromBuffer(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_DATA:
                        return _message = new ChannelData(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA:
                        return _message = new ChannelExtendedData(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_SUCCESS:
                        return _message = new ChannelSuccess(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_FAILURE:
                        return _message = new ChannelFailure(Buffer);
                    case MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                        return _message = new ChannelWindowAdjust(Buffer);
                    default:
                        return _message;
                }
            }
        }
    }
}
