using System;
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
        /// <param name="packet">
        /// The packet containing the message data.
        /// </param>
        public MessageEvent(SshPacket packet)
        {
            Packet = packet;
            TypeId = packet.Reader.ReadByte();
            Type = (MessageType)TypeId;
        }

        /// <summary>
        /// Gets the raw buffer of the message.
        /// </summary>
        public SshPacket Packet { get; }

        /// <summary>
        /// Gets the message type code.
        /// </summary>
        public byte TypeId { get; }

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

                switch (Type)
                {
                    case MessageType.SSH_MSG_KEXINIT:
                        return _message = new KexInit(Packet);
                    case MessageType.SSH_MSG_NEWKEYS:
                        return _message = new NewKeys();
                    case MessageType.SSH_MSG_IGNORE:
                        return _message = new Ignore(Packet);
                    case MessageType.SSH_MSG_UNIMPLEMENTED:
                        return _message = new Unimplemented(Packet);
                    case MessageType.SSH_MSG_DISCONNECT:
                        return _message = new Disconnect(Packet);
                    case MessageType.SSH_MSG_SERVICE_ACCEPT:
                        return _message = new ServiceAccept(Packet);
                    case MessageType.SSH_MSG_USERAUTH_INFO_REQUEST:
                        return _message = new UaInfoRequest(Packet);
                    case MessageType.SSH_MSG_USERAUTH_FAILURE:
                        return _message = new UaFailure();
                    case MessageType.SSH_MSG_USERAUTH_SUCCESS:
                        return _message = new UaSuccess();
                    case MessageType.SSH_MSG_USERAUTH_BANNER:
                        return _message = new UaBanner(Packet);
                    case MessageType.SSH_MSG_CHANNEL_OPEN:
                        return _message = ChannelOpen.FromBuffer(Packet);
                    case MessageType.SSH_MSG_CHANNEL_CLOSE:
                        return _message = new ChannelClose(Packet);
                    case MessageType.SSH_MSG_CHANNEL_EOF:
                        return _message = new ChannelEof(Packet);
                    case MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                        return _message = new ChannelOpenConfirmation(Packet);
                    case MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE:
                        return _message = new ChannelOpenFailure(Packet);
                    case MessageType.SSH_MSG_CHANNEL_REQUEST:
                        return _message = ChannelRequest.FromBuffer(Packet);
                    case MessageType.SSH_MSG_CHANNEL_DATA:
                        return _message = new ChannelData(Packet);
                    case MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA:
                        return _message = new ChannelExtendedData(Packet);
                    case MessageType.SSH_MSG_CHANNEL_SUCCESS:
                        return _message = new ChannelSuccess(Packet);
                    case MessageType.SSH_MSG_CHANNEL_FAILURE:
                        return _message = new ChannelFailure(Packet);
                    case MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                        return _message = new ChannelWindowAdjust(Packet);
                    default:
                        return _message;
                }
            }
        }
    }
}
