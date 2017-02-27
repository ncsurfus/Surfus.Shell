using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using NLog;

namespace Surfus.Shell
{
    internal class SshChannel
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();
        // Message Sources
        // MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION OR MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION OR
        internal TaskCompletionSource<ChannelOpenConfirmation> ChannelOpenConfirmationMessage = new TaskCompletionSource<ChannelOpenConfirmation>();

        // MessageType.SSH_MSG_CHANNEL_SUCCESS OR MessageType.SSH_MSG_CHANNEL_FAILURE
        internal TaskCompletionSource<ChannelSuccess> ChannelSuccessMessage = new TaskCompletionSource<ChannelSuccess>();

        private bool _channelClosed;
        private bool _channelOpened;

        public SshClient SshClient { get; }

        public int WindowRefill { get; internal set; } = 50000;
        public int SendWindow { get; internal set; }
        public int ReceiveWindow { get; internal set; }
        public uint ServerId { get; internal set; }
        public uint ClientId { get; internal set; }
        public Func<byte[], CancellationToken, Task> OnDataReceived;
        public Func<ChannelEof, CancellationToken, Task> OnChannelEofReceived;
        public Func<ChannelClose, CancellationToken, Task> OnChannelCloseReceived;
        public bool IsOpen => !SshClient.IsFinished && _channelOpened && !_channelClosed;

        internal SshChannel(SshClient sshClient, uint channelId)
        {
            SshClient = sshClient;
            ClientId = channelId;
        }

        public async Task WriteDataAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            var totalBytesLeft = buffer.Length;
            while (totalBytesLeft > 0)
            {
                if (totalBytesLeft <= SendWindow)
                {
                    await SshClientStaticThread.WriteMessageAsync(SshClient, new ChannelData(ServerId, buffer), cancellationToken);
                    SendWindow -= totalBytesLeft;
                    totalBytesLeft = 0;
                }
                else
                {
                    var smallBuffer = new byte[SendWindow];
                    Array.Copy(buffer, smallBuffer, smallBuffer.Length);
                    await SshClientStaticThread.WriteMessageAsync(SshClient, new ChannelData(ServerId, smallBuffer), cancellationToken);
                    totalBytesLeft -= SendWindow;
                    SendWindow = 0;
                }
            }
        }

        public async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            await SshClientStaticThread.WriteMessageAsync(SshClient, requestMessage, cancellationToken);
            var openResponse = await ChannelSuccessMessage.Task;
        }

        public async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            if (IsOpen)
            {
                throw new SshException("Channel already open.");
            }

            ReceiveWindow = (int)openMessage.InitialWindowSize;
            await SshClientStaticThread.WriteMessageAsync(SshClient, openMessage, cancellationToken);
   
            var openResponse = await ChannelOpenConfirmationMessage.Task;
            ServerId = openResponse.SenderChannel;
            SendWindow = (int)openResponse.InitialWindowSize;
            _channelOpened = true;
        }

        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (!IsOpen)
            {
                throw new SshException("Channel already closed.");
            }

            await SshClientStaticThread.WriteMessageAsync(SshClient, new ChannelClose(ServerId), cancellationToken);
            _channelClosed = true;
        }

        public void SendMessage(ChannelOpenConfirmation message)
        {
            logger.Trace("Setting OpenConfirmation");
            ChannelOpenConfirmationMessage.TrySetResult(message);
        }

        public void SendMessage(ChannelOpenFailure message)
        {
            ChannelOpenConfirmationMessage.TrySetException(new SshException("Server failed to open channel"));
        }

        public void SendMessage(ChannelSuccess message)
        {
            ChannelSuccessMessage.TrySetResult(message);
        }

        public void SendMessage(ChannelFailure message)
        {
            ChannelSuccessMessage.TrySetException(new SshException("Server had channel request failure."));
        }

        public void SendMessage(ChannelWindowAdjust message)
        {
            SendWindow += (int)message.BytesToAdd;
        }

        public async Task SendMessageAsync(ChannelData message, CancellationToken cancellationToken)
        {
            if (ReceiveWindow <= 0)
            {
                return;
            }

            var length = message.Data.Length > ReceiveWindow ? ReceiveWindow : message.Data.Length;
            if (length != message.Data.Length)
            {
                message.ResizeData(length);
            }

            ReceiveWindow -= length;

            if (ReceiveWindow <= 0)
            {
                await SshClientStaticThread.WriteMessageAsync(SshClient, new ChannelWindowAdjust(ServerId, (uint)WindowRefill), cancellationToken);
                ReceiveWindow += WindowRefill;
            }

            if(OnDataReceived != null)
            {
                await OnDataReceived(message.Data, cancellationToken);
            }
        }

        public async Task SendMessageAsync(ChannelEof message, CancellationToken cancellationToken)
        {
            if (OnChannelEofReceived != null)
            {
                await OnChannelEofReceived(message, cancellationToken);
            }
        }

        public async Task SendMessageAsync(ChannelClose message, CancellationToken cancellationToken)
        {
            if (OnChannelCloseReceived != null)
            {
                await OnChannelCloseReceived(message, cancellationToken);
            }
        }
    }
}
