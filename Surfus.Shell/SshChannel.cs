using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using NLog;

namespace Surfus.Shell
{
    internal class SshChannel : IDisposable
    {
        // Fields
        private static Logger _logger = LogManager.GetCurrentClassLogger();
        private readonly SemaphoreSlim _channelSemaphore = new SemaphoreSlim(1, 1);
        private State _channelState = new State();
        private bool _isDisposed;

        // Properities
        private TaskCompletionSource<bool> _channelOpenCompleted;
        private TaskCompletionSource<bool> _channelRequestCompleted;


        private bool _channelClosed;
        private bool _channelOpened;

        private SshClient _client;

        public int WindowRefill { get; internal set; } = 50000;
        public int SendWindow { get; internal set; }
        public int ReceiveWindow { get; internal set; }
        public uint ServerId { get; internal set; }
        public uint ClientId { get; internal set; }
        public Func<byte[], CancellationToken, Task> OnDataReceived;
        public Func<ChannelEof, CancellationToken, Task> OnChannelEofReceived;
        public Func<ChannelClose, CancellationToken, Task> OnChannelCloseReceived;
        public bool IsOpen => _channelState != State.Initial && _channelState != State.Errored && _channelState != State.Closed;

        internal SshChannel(SshClient client, uint channelId)
        {
            _client = client;
            ClientId = channelId;
        }

        // This will be called by the user, NOT the Read Loop
        public async Task WriteDataAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);

            var totalBytesLeft = buffer.Length;
            while (totalBytesLeft > 0)
            {
                if (totalBytesLeft <= SendWindow)
                {
                    await _client.WriteMessageAsync(new ChannelData(ServerId, buffer), cancellationToken);
                    SendWindow -= totalBytesLeft;
                    totalBytesLeft = 0;
                }
                else
                {
                    var smallBuffer = new byte[SendWindow];
                    Array.Copy(buffer, smallBuffer, smallBuffer.Length);
                    await _client.WriteMessageAsync(new ChannelData(ServerId, smallBuffer), cancellationToken);
                    totalBytesLeft -= SendWindow;
                    SendWindow = 0;
                }
            }

            _channelSemaphore.Release();
        }


        // This will be called by the user, NOT the Read Loop....
        public async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);

            if (_channelState != State.ChannelIsOpen)
            {
                throw new Exception("Channel is not ready for request.");
            }

            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _client.InternalCancellation.Token))
            {
                _channelRequestCompleted = new TaskCompletionSource<bool>();
                await _client.WriteMessageAsync(requestMessage, cancellationToken);
                _channelState = State.WaitingOnRequestResponse;
                _channelSemaphore.Release();
                await _channelRequestCompleted.Task;
            }
        }

        // This will be called by the user, NOT the Read Loop....
        public async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);

            if (_channelState != State.Initial)
            {
                throw new Exception("Channel is already open");
            }

            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _client.InternalCancellation.Token))
            {
                _channelOpenCompleted = new TaskCompletionSource<bool>();
                ReceiveWindow = (int)openMessage.InitialWindowSize;
                await _client.WriteMessageAsync(openMessage, cancellationToken);
                _channelState = State.WaitingOnOpenConfirmation;
                _channelSemaphore.Release();
                await _channelOpenCompleted.Task;
            }
        }

        // This will be called by the user NOT the Read Loops....
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync();

            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
               await _client.WriteMessageAsync(new ChannelClose(ServerId), cancellationToken);
                _channelState = State.Closed;
                Close();
            }

            _channelSemaphore.Release();
        }

        public async Task SendMessageAsync(ChannelOpenConfirmation message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);
            if (_channelState != State.WaitingOnOpenConfirmation)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            ServerId = message.SenderChannel;
            SendWindow = (int)message.InitialWindowSize;
            _channelState = State.ChannelIsOpen;

            _channelOpenCompleted?.TrySetResult(true);

            _channelSemaphore.Release();
        }

        public async Task SendMessageAsync(ChannelOpenFailure message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);
            if (_channelState != State.WaitingOnOpenConfirmation)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            var exception = new SshException("Server refused to open channel."); ;
            _channelState = State.Errored;
            _channelOpenCompleted?.TrySetException(exception);
            _channelSemaphore.Release();
            throw exception;
        }

        public async Task SendMessageAsync(ChannelSuccess message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);
            if (_channelState != State.WaitingOnRequestResponse)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            // Reset state to ChannelIsOpen
            _channelState = State.ChannelIsOpen;
            _channelRequestCompleted?.TrySetResult(true);

            _channelSemaphore.Release();
        }

        public async Task SendMessageAsync(ChannelFailure message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);
            if (_channelState != State.WaitingOnRequestResponse)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            var exception = new SshException("Server had channel request failure."); ;
            _channelState = State.Errored;
            _channelRequestCompleted?.TrySetException(exception);
            _channelSemaphore.Release();
            throw exception;
        }

        public async Task SendMessageAsync(ChannelWindowAdjust message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }


            SendWindow += (int)message.BytesToAdd;
            _channelSemaphore.Release();
        }

        public async Task SendMessageAsync(ChannelData message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            if (ReceiveWindow <= 0)
            {
                _channelSemaphore.Release();
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
                await _client.WriteMessageAsync(new ChannelWindowAdjust(ServerId, (uint)WindowRefill), cancellationToken);
                ReceiveWindow += WindowRefill;
            }

            if (OnDataReceived != null)
            {
                await OnDataReceived(message.Data, cancellationToken);
            }

            _channelSemaphore.Release();
        }

        public async Task SendMessageAsync(ChannelEof message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            if (OnChannelEofReceived != null)
            {
                await OnChannelEofReceived(message, cancellationToken);
            }

            _channelSemaphore.Release();
        }

        public async Task SendMessageAsync(ChannelClose message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken);
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            if (OnChannelCloseReceived != null)
            {
                await OnChannelCloseReceived(message, cancellationToken);
            }

            _channelSemaphore.Release();
        }

        public void Close()
        {
            if(!_isDisposed)
            {
                _isDisposed = true;
                _channelSemaphore.Dispose();
            }
        }

        public void Dispose()
        {
            Close();
        }

        internal enum State
        {
            Initial,
            WaitingOnOpenConfirmation,
            ChannelIsOpen,
            WaitingOnRequestResponse,
            Closed,
            Errored
        }
    }
}
