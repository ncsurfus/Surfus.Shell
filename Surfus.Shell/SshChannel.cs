using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;
using Microsoft.Extensions.Logging;
using System.Text;

namespace Surfus.Shell
{
    internal class SshChannel : IDisposable
    {
        // Fields
        private ILogger _logger;
        private readonly SemaphoreSlim _channelSemaphore = new SemaphoreSlim(1, 1);
        private State _channelState = new State();
        private bool _isDisposed;
        private SshClient _client;

        // Properities
        private TaskCompletionSource<bool> _channelOpenCompleted;
        private TaskCompletionSource<bool> _channelRequestCompleted;

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
            _logger = _logger = _client.Logger;
        }

        // This will be called by the user, NOT the Read Loop
        public async Task WriteDataAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _client.InternalCancellation.Token))
            {
                var totalBytesLeft = buffer.Length;
                while (totalBytesLeft > 0)
                {
                    _logger.LogInformation("WriteDataAsync is getting Semaphore");
                    await _channelSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                    _logger.LogInformation("WriteDataAsync has Semaphore");
                    _logger.LogInformation("SendWindow is " + SendWindow);
                    if (totalBytesLeft <= SendWindow)
                    {
                        _logger.LogInformation("WriteDataAsync is sending data to WriteMessageAsync");
                        await _client.WriteMessageAsync(new ChannelData(ServerId, buffer), linkedCancellation.Token).ConfigureAwait(false);
                        SendWindow -= totalBytesLeft;
                        totalBytesLeft = 0;
                    }
                    else
                    {
                        var smallBuffer = new byte[SendWindow];
                        Array.Copy(buffer, smallBuffer, smallBuffer.Length);
                        _logger.LogInformation("WriteDataAsync is sending a portion of the data to WriteMessageAsync.");
                        await _client.WriteMessageAsync(new ChannelData(ServerId, smallBuffer), linkedCancellation.Token).ConfigureAwait(false);
                        totalBytesLeft -= SendWindow;
                        SendWindow = 0;
                    }
                    _logger.LogInformation("WriteDataAsync has released Semaphore");
                    _channelSemaphore.Release();
                    await Task.Delay(100, linkedCancellation.Token).ConfigureAwait(false);
                }
            }
        }

        // This will be called by the user, NOT the Read Loop....
        public async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_channelState != State.ChannelIsOpen)
            {
                throw new Exception("Channel is not ready for request.");
            }

            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _client.InternalCancellation.Token))
            {
                _channelRequestCompleted = new TaskCompletionSource<bool>();
                await _client.WriteMessageAsync(requestMessage, linkedCancellation.Token).ConfigureAwait(false);
                _channelState = State.WaitingOnRequestResponse;
                _channelSemaphore.Release();
                await _channelRequestCompleted.Task.ConfigureAwait(false);
            }
        }

        // This will be called by the user, NOT the Read Loop....
        public async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _client.InternalCancellation.Token))
            {
                await _channelSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_channelState != State.Initial)
                {
                    throw new Exception("Channel is already open");
                }

                _channelOpenCompleted = new TaskCompletionSource<bool>();
                ReceiveWindow = (int)openMessage.InitialWindowSize;
                await _client.WriteMessageAsync(openMessage, linkedCancellation.Token).ConfigureAwait(false);
                _channelState = State.WaitingOnOpenConfirmation;
                _channelSemaphore.Release();
                await _channelOpenCompleted.Task.ConfigureAwait(false);
            }
        }

        // This will be called by the user NOT the Read Loops....
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _client.InternalCancellation.Token))
            {
                await _channelSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
                {
                    await _client.WriteMessageAsync(new ChannelClose(ServerId), linkedCancellation.Token).ConfigureAwait(false);
                    _channelState = State.Closed;
                    Close();
                }
                _channelSemaphore.Release();
            }
        }

        public async Task SendMessageAsync(ChannelOpenConfirmation message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
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
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
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
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
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
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
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
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            SendWindow += (int)message.BytesToAdd;
            _logger.LogInformation($"Send window has been increased {SendWindow}");
            _channelSemaphore.Release();
        }

        public async Task SendMessageAsync(ChannelData message, CancellationToken cancellationToken)
        {
            _logger.LogInformation("SendMessageAsync (ChannelData) is getting Semaphore");
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("SendMessageAsync (ChannelData) has got the Semaphore");
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                _logger.LogInformation("SendMessageAsync (ChannelData) has released the Semaphore and thrown an exception");
                throw new SshException("Received unexpected channel message.");
            }

            if (ReceiveWindow <= 0)
            {
                _channelSemaphore.Release();
                _logger.LogInformation("SendMessageAsync (ChannelData) has released the Semaphore, as the ReceiveWindow is under 0");
                return;
            }

            var length = message.Data.Length > ReceiveWindow ? ReceiveWindow : message.Data.Length;
            if (length != message.Data.Length)
            {
                _logger.LogInformation($"Server sent to much data, resizing from {message.Data.Length} to {ReceiveWindow}");
                message.ResizeData(length);
            }

            ReceiveWindow -= length;

            if (ReceiveWindow <= 0)
            {
                _logger.LogInformation("SendMessageAsync (ChannelData) is waiting on the client to send a message to increase the ChannelWindow");
                await _client.WriteMessageAsync(new ChannelWindowAdjust(ServerId, (uint)WindowRefill), cancellationToken).ConfigureAwait(false);
                ReceiveWindow += WindowRefill;
            }

            if (OnDataReceived != null)
            {
                _logger.LogInformation("SendMessageAsync (ChannelData) is waiting the upper level object.");
                await OnDataReceived(message.Data, cancellationToken).ConfigureAwait(false);
                _logger.LogInformation("SendMessageAsync (ChannelData) has completed sending the data to the upper level object.");
            }

            _channelSemaphore.Release();
            _logger.LogInformation("SendMessageAsync (ChannelData) has released the Semaphore");
        }

        public async Task SendMessageAsync(ChannelEof message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            if (OnChannelEofReceived != null)
            {
                await OnChannelEofReceived(message, cancellationToken).ConfigureAwait(false);
            }

            _channelSemaphore.Release();
        }

        public async Task SendMessageAsync(ChannelClose message, CancellationToken cancellationToken)
        {
            await _channelSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                _channelSemaphore.Release();
                throw new SshException("Received unexpected channel message.");
            }

            if (OnChannelCloseReceived != null)
            {
                await OnChannelCloseReceived(message, cancellationToken).ConfigureAwait(false);
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
