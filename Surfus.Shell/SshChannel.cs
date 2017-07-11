﻿using System;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages.Channel;

namespace Surfus.Shell
{
    /// <summary>
    /// Repesents an SSH Channel. Once the SSH connections is setup channels are created and data can be passed.
    /// </summary>
    internal class SshChannel : IDisposable
    {
        /// <summary>
        /// The state of the channel.
        /// </summary>
        private State _channelState = State.Initial;

        /// <summary>
        /// The disposed state of the channel.
        /// </summary>
        private bool _isDisposed;

        /// <summary>
        /// The SshClient that owns the channel.
        /// </summary>
        private SshClient _client;

        /// <summary>
        /// This is set once the channel open response is received.
        /// </summary>
        private TaskCompletionSource<bool> _channelOpenCompleted;

        /// <summary>
        /// This is set once the channel request response is received.
        /// </summary>
        private TaskCompletionSource<bool> _channelRequestCompleted;

        /// <summary>
        /// The amount of data to increase by once the receive window is empty.
        /// </summary>
        internal int WindowRefill { get; set; } = 50000;

        /// <summary>
        /// The amount of data we are allowed to send to the server.
        /// </summary>
        internal int SendWindow { get; set; }

        /// <summary>
        /// The amount of data that can be sent to us.
        /// </summary>
        internal int ReceiveWindow { get; set; }

        /// <summary>
        /// The id assigned to us by the server that represents this channel.
        /// </summary>
        internal uint ServerId { get; set; }

        /// <summary>
        /// The id we've assigned to the server that represents this channel.
        /// </summary>
        internal uint ClientId { get; set; }

        /// <summary>
        /// A callback once data is received.
        /// </summary>
        internal Action<byte[]> OnDataReceived;

        /// <summary>
        /// A callback when a channel end of file is received.
        /// </summary>
        internal Action<ChannelEof> OnChannelEofReceived;

        /// <summary>
        /// A callback when a channel close is received.
        /// </summary>
        internal Action<ChannelClose> OnChannelCloseReceived;

        /// <summary>
        /// Returns the open/close state of the channel.
        /// </summary>
        internal bool IsOpen => _channelState != State.Initial && _channelState != State.Errored && _channelState != State.Closed;

        /// <summary>
        /// A channel used to pass data, open terminals, and run commands.
        /// </summary>
        /// <param name="client">The SshClient that owns this channel.</param>
        /// <param name="channelId">The channel id used to uniquely represent this channel.</param>
        internal SshChannel(SshClient client, uint channelId)
        {
            _client = client;
            ClientId = channelId;
        }

        /// <summary>
        /// Writes data over the SSH channel.
        /// </summary>
        /// <param name="buffer">The data to send over the channel.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task WriteDataAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            var totalBytesLeft = buffer.Length;
            while (totalBytesLeft > 0)
            {
                if (totalBytesLeft <= SendWindow)
                {
                    await _client.WriteMessageAsync(new ChannelData(ServerId, buffer), cancellationToken).ConfigureAwait(false);
                    SendWindow -= totalBytesLeft;
                    totalBytesLeft = 0;
                }
                else
                {
                    var smallBuffer = new byte[SendWindow];
                    Array.Copy(buffer, smallBuffer, smallBuffer.Length);
                    await _client.WriteMessageAsync(new ChannelData(ServerId, smallBuffer), cancellationToken).ConfigureAwait(false);
                    totalBytesLeft -= SendWindow;
                    SendWindow = 0;
                    await _client.ReadUntilAsync(() => SendWindow > 0, cancellationToken);
                }
            }
        }

        /// <summary>
        /// Requests the channel to be opened.
        /// </summary>
        /// <param name="requestMessage">The request message that defines what type of channel should be opened.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            if (_channelState != State.ChannelIsOpen)
            {
                throw new Exception("Channel is not ready for request.");
            }

            _channelRequestCompleted = new TaskCompletionSource<bool>();
            await _client.WriteMessageAsync(requestMessage, cancellationToken).ConfigureAwait(false);
            _channelState = State.WaitingOnRequestResponse;
            await _channelRequestCompleted.Task.ConfigureAwait(false);
        }

        /// <summary>
        /// Opens the channel.
        /// </summary>
        /// <param name="openMessage">The channel open messages that defines the opening parameters of the channel.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            if (_channelState != State.Initial)
            {
                throw new Exception("Channel is already open");
            }

            _channelOpenCompleted = new TaskCompletionSource<bool>();
            ReceiveWindow = (int)openMessage.InitialWindowSize;
            await _client.WriteMessageAsync(openMessage, cancellationToken).ConfigureAwait(false);
            _channelState = State.WaitingOnOpenConfirmation;
            await _channelOpenCompleted.Task.ConfigureAwait(false);
        }

        /// <summary>
        /// Closes the channel.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                await _client.WriteMessageAsync(new ChannelClose(ServerId), cancellationToken).ConfigureAwait(false);
                _channelState = State.Closed;
                Close();
            }
        }

        /// <summary>
        /// Processes a channel message that was sent by the server.
        /// </summary>
        /// <param name="message">The open confirmation message that was sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(ChannelOpenConfirmation message, CancellationToken cancellationToken)
        {
            if (_channelState != State.WaitingOnOpenConfirmation)
            {
                _channelState = State.Errored;
                throw new SshException("Received unexpected channel message.");
            }

            ServerId = message.SenderChannel;
            SendWindow = (int)message.InitialWindowSize;
            _channelState = State.ChannelIsOpen;

            _channelOpenCompleted?.TrySetResult(true);
        }

        /// <summary>
        /// Processes a channel message that was sent by the server.
        /// </summary>
        /// <param name="message">The open failure message that was sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(ChannelOpenFailure message, CancellationToken cancellationToken)
        {
            if (_channelState != State.WaitingOnOpenConfirmation)
            {
                _channelState = State.Errored;
                throw new SshException("Received unexpected channel message.");
            }

            var exception = new SshException("Server refused to open channel."); ;
            _channelState = State.Errored;
            _channelOpenCompleted?.TrySetException(exception);
            throw exception;
        }

        /// <summary>
        /// Processes a channel message that was sent by the server.
        /// </summary>
        /// <param name="message">The channel success message that was sent by the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(ChannelSuccess message, CancellationToken cancellationToken)
        {
            if (_channelState != State.WaitingOnRequestResponse)
            {
                _channelState = State.Errored;
                throw new SshException("Received unexpected channel message.");
            }

            // Reset state to ChannelIsOpen
            _channelState = State.ChannelIsOpen;
            _channelRequestCompleted?.TrySetResult(true);
        }

        /// <summary>
        /// Processes a channel message that was sent by the server.
        /// </summary>
        /// <param name="message">The channel failure message that was sent by the server.</param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(ChannelFailure message, CancellationToken cancellationToken)
        {
            if (_channelState != State.WaitingOnRequestResponse)
            {
                _channelState = State.Errored;
                throw new SshException("Received unexpected channel message.");
            }

            var exception = new SshException("Server had channel request failure."); ;
            _channelState = State.Errored;
            _channelRequestCompleted?.TrySetException(exception);
            throw exception;
        }

        /// <summary>
        /// Processes a channel message that was sent by the server.
        /// </summary>
        /// <param name="message">The channel window adjust sent by the server. Once this is sent to us we can send more data.</param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(ChannelWindowAdjust message, CancellationToken cancellationToken)
        {
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                throw new SshException("Received unexpected channel message.");
            }

            SendWindow += (int)message.BytesToAdd;        }

        /// <summary>
        /// Processes a channel message that was sent by the server.
        /// </summary>
        /// <param name="message">The channel data sent by the server. This contains data that we will send in the callback method.</param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task ProcessMessageAsync(ChannelData message, CancellationToken cancellationToken)
        {
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                throw new SshException("Received unexpected channel message.");
            }

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
                await _client.WriteMessageAsync(new ChannelWindowAdjust(ServerId, (uint)WindowRefill), cancellationToken).ConfigureAwait(false);
                ReceiveWindow += WindowRefill;
            }

            OnDataReceived?.Invoke(message.Data);
        }

        /// <summary>
        /// Processes a channel message that was sent by the server.
        /// </summary>
        /// <param name="message">The channel end of file sent by the server. We could still send data, but the server has stopped.</param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(ChannelEof message, CancellationToken cancellationToken)
        {
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                throw new SshException("Received unexpected channel message.");
            }

            OnChannelEofReceived?.Invoke(message);
        }

        /// <summary>
        /// Processes a channel message that was sent by the server.
        /// </summary>
        /// <param name="message">The channel close message sent by the server.</param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal void ProcessMessageAsync(ChannelClose message, CancellationToken cancellationToken)
        {
            if (_channelState == State.Initial || _channelState == State.Errored || _channelState == State.Closed)
            {
                _channelState = State.Errored;
                throw new SshException("Received unexpected channel message.");
            }

            OnChannelCloseReceived?.Invoke(message);
        }

        /// <summary>
        /// Closes the channel.
        /// </summary>
        public void Close()
        {
            if(!_isDisposed)
            {
                _isDisposed = true;
            }
        }

        /// <summary>
        /// Disposes the channel.
        /// </summary>
        public void Dispose()
        {
            Close();
        }

        /// <summary>
        /// The states the channel can be in.
        /// </summary>
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
