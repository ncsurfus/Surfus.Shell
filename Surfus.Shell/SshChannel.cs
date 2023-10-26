using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel;

namespace Surfus.Shell
{
    public enum ExtendedDataHandling
    {
        IGNORE,
        MERGE,
        QUEUE,
    }

    public class SshChannel : IAsyncDisposable
    {
        private readonly SshClient _client;
        private readonly TaskCompletionSource _close = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _eof = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly CancellationTokenSource _cts = new();
        private readonly Task _backgroundTask;
        private readonly Exception _ex;

        private readonly SemaphoreSlim _readSemaphore = new(1, 1);
        private readonly SemaphoreSlim _sendSemaphore = new(1, 1);

        private int _sendWindow = 0;
        private int _receiveWindow = 0;
        private int _queuedBytes = 0;

        private readonly object _lock = new();
        private readonly Channel<Memory<byte>> DataReceived = Channel.CreateUnbounded<Memory<byte>>(new UnboundedChannelOptions
        {
            SingleWriter = true,
        });
        private readonly Channel<(Memory<byte> Data, uint Stream)> ExtendedDataReceived = Channel.CreateUnbounded<(Memory<byte> Data, uint Stream)>(new UnboundedChannelOptions
        {
            SingleWriter = true,
        });

        private readonly Channel<int> WindowAdjust = Channel.CreateUnbounded<int>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
        });

        /// <summary>
        /// A channel used to pass data, open terminals, and run commands.
        /// </summary>
        /// <param name="client">The SshClient that owns this channel.</param>
        /// <param name="channelId">The channel id used to uniquely represent this channel.</param>
        internal SshChannel(SshClient client, uint channelId)
        {
            _client = client;
            ClientId = channelId;
            _backgroundTask = Task.Run(async () =>
            {
                try
                {
                    await Task.WhenAll(HandleAsync(_cts.Token), ProcessWindowMessageAsync(_cts.Token));
                }
                catch (Exception ex)
                {
                    _eof.TrySetException(ex);
                    _close.TrySetException(ex);
                    DataReceived.Writer.TryComplete(ex);
                    WindowAdjust.Writer.TryComplete(ex);
                    throw;
                }
                finally
                {
                    _cts.Cancel();
                }
            });
        }

        public TimeSpan CloseTimeout { get; init; } = TimeSpan.FromSeconds(10);

        public int Window { get; init; } = 2_097_152;

        public ExtendedDataHandling ExtendedDataHandling { get; init; } = ExtendedDataHandling.MERGE;

        /// <summary>
        /// The server's channel id.
        /// </summary>
        public uint ServerId { get; private set; }

        /// <summary>
        /// The client's channel id.
        /// </summary>
        public uint ClientId { get; private set; }

        /// <summary>
        /// Completes when the channel is closed.
        /// </summary>
        public Task ChannelClosed => _close.Task;

        /// <summary>
        /// Completes when the channel is closed or remote end indicates no more data will be sent.
        /// </summary>
        public Task ChannelEof => _eof.Task;

        private async Task ProcessWindowMessageAsync(CancellationToken cancellationToken)
        {
            // Maybe handle this logic in the "switch", but just have a "Window Adjust indicator"?
            // Perhaps a 1 buffer channel?
            while (true)
            {
                await WindowAdjust.Reader.WaitToReadAsync(CancellationToken.None).ConfigureAwait(false);
                await _sendSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    while (WindowAdjust.Reader.TryRead(out var windowSizeIncrease))
                    {
                        _sendWindow += windowSizeIncrease;
                    }
                }
                finally
                {
                    _sendSemaphore.Release();
                }
            }
        }

        private async Task UpdateWindow(int length, CancellationToken cancellationToken)
        {
            if (length == 0)
            {
                return;
            }

            await _readSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (length > _receiveWindow)
                {
                    throw new Exception("Server exceeded ReceiveWindow!");
                }
                _receiveWindow -= length;
                _queuedBytes += length;
            }
            finally
            {
                _readSemaphore.Release();
            }
        }

        private async Task HandleAsync(CancellationToken cancellationToken)
        {
            bool FilterMessage(MessageEvent message)
            {
                if (message.Message is not IChannelRecipient msg || msg.RecipientChannel != ClientId)
                {
                    return false;
                }

                return message.Type switch
                {
                    MessageType.SSH_MSG_CHANNEL_EOF
                    or MessageType.SSH_MSG_CHANNEL_CLOSE
                    or MessageType.SSH_MSG_CHANNEL_DATA
                    or MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA
                    or MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST
                        => true,
                    _ => false,
                };
            }

            var channelReader = _client.RegisterMessageHandler(FilterMessage);
            try
            {
                while (true)
                {
                    var message = await channelReader.ReadAsync(cancellationToken);
                    switch (message.Message)
                    {
                        case ChannelEof eof:
                            _eof.TrySetResult();
                            DataReceived.Writer.TryComplete();
                            ExtendedDataReceived.Writer.TryComplete();
                            break;
                        case ChannelClose close:
                            _close.TrySetResult();
                            throw new Exception("Channel closed!");
                        case ChannelExtendedData data when ExtendedDataHandling == ExtendedDataHandling.IGNORE:
                            await UpdateWindow(data.Data.Length, cancellationToken).ConfigureAwait(false);
                            break;
                        case ChannelExtendedData data when ExtendedDataHandling == ExtendedDataHandling.QUEUE:
                            await UpdateWindow(data.Data.Length, cancellationToken).ConfigureAwait(false);
                            await ExtendedDataReceived.Writer.WriteAsync((data.Data, (uint)data.DataTypeCode), cancellationToken).ConfigureAwait(false);
                            break;
                        case ChannelExtendedData data when ExtendedDataHandling == ExtendedDataHandling.MERGE:
                            await UpdateWindow(data.Data.Length, cancellationToken).ConfigureAwait(false);
                            await DataReceived.Writer.WriteAsync(data.Data, cancellationToken).ConfigureAwait(false);
                            break;
                        case ChannelData data:
                            await UpdateWindow(data.Data.Length, cancellationToken).ConfigureAwait(false);
                            await DataReceived.Writer.WriteAsync(data.Data, cancellationToken).ConfigureAwait(false);
                            break;
                        case ChannelWindowAdjust windowAdjust:
                            await WindowAdjust.Writer.WriteAsync((int)windowAdjust.BytesToAdd, cancellationToken);
                            break;
                    }
                }
            }
            finally
            {
                _client.DeregisterMessageHandler(channelReader);
            }
        }

        /// <summary>
        /// Writes data over the SSH channel.
        /// </summary>
        /// <param name="buffer">The data to send over the channel.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        public async Task WriteDataAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            await _sendSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var totalBytesLeft = buffer.Length;
                while (totalBytesLeft > 0)
                {
                    if (totalBytesLeft <= _sendWindow)
                    {
                        await _client.WriteMessageAsync(new ChannelData(ServerId, buffer), cancellationToken).ConfigureAwait(false);
                        _sendWindow -= totalBytesLeft;
                        totalBytesLeft = 0;
                    }
                    else
                    {
                        if (_sendWindow > 0)
                        {
                            // TODO: Simplify with Memory<byte>
                            var smallBuffer = new byte[_sendWindow];
                            Array.Copy(buffer, smallBuffer, smallBuffer.Length);
                            await _client.WriteMessageAsync(new ChannelData(ServerId, smallBuffer), cancellationToken).ConfigureAwait(false);
                            totalBytesLeft -= _sendWindow;
                            _sendWindow = 0;
                        }
                        _sendWindow += await WindowAdjust.Reader.ReadAsync(cancellationToken);
                    }
                }
            }
            finally
            {
                _sendSemaphore.Release();
            }
        }

        /// <summary>
        /// Writes extended data over the SSH channel.
        /// </summary>
        public async Task WriteExtendedDataAsync(byte[] buffer, uint stream, CancellationToken cancellationToken)
        {
            await _sendSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var totalBytesLeft = buffer.Length;
                while (totalBytesLeft > 0)
                {
                    if (totalBytesLeft <= _sendWindow)
                    {
                        await _client.WriteMessageAsync(new ChannelExtendedData(ServerId, stream, buffer), cancellationToken).ConfigureAwait(false);
                        _sendWindow -= totalBytesLeft;
                        totalBytesLeft = 0;
                    }
                    else
                    {
                        if (_sendWindow > 0)
                        {
                            // TODO: Simplify with Memory<byte>
                            var smallBuffer = new byte[_sendWindow];
                            Array.Copy(buffer, smallBuffer, smallBuffer.Length);
                            await _client.WriteMessageAsync(new ChannelExtendedData(ServerId, stream, smallBuffer), cancellationToken).ConfigureAwait(false);
                            totalBytesLeft -= _sendWindow;
                            _sendWindow = 0;
                        }
                        _sendWindow += await WindowAdjust.Reader.ReadAsync(cancellationToken);
                    }
                }
            }
            finally
            {
                _sendSemaphore.Release();
            }
        }

        public async Task<Memory<byte>> ReadDataAsync(CancellationToken cancellationToken)
        {
            Memory<byte> data;
            try
            {
                data = await DataReceived.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException)
            {
                return Memory<byte>.Empty;
            }

            await _readSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                _queuedBytes -= data.Length;
                if (_receiveWindow + _queuedBytes == 0)
                {
                    await _client.WriteMessageAsync(new ChannelWindowAdjust(ServerId, (uint)Window), cancellationToken);
                    _receiveWindow += Window;
                }
            }
            finally
            {
                _readSemaphore.Release();
            }

            return data;
        }

        /// <summary>
        /// Requests the channel to be opened.
        /// </summary>
        /// <param name="requestMessage">The request message that defines what type of channel should be opened.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task RequestAsync(ChannelRequest requestMessage, CancellationToken cancellationToken)
        {
            bool FilterMessage(MessageEvent message)
            {
                if (message.Message is not IChannelRecipient msg || msg.RecipientChannel != ClientId)
                {
                    return false;
                }

                return message.Type switch
                {
                    MessageType.SSH_MSG_CHANNEL_SUCCESS
                    or MessageType.SSH_MSG_CHANNEL_FAILURE
                        => true,
                    _ => false,
                };
            }

            var channelReader = _client.RegisterMessageHandler(FilterMessage);
            try
            {
                // Send request message...
                await _client.WriteMessageAsync(requestMessage, cancellationToken).ConfigureAwait(false);

                // Check if this was allowed..
                var message = await channelReader.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (message.Type == MessageType.SSH_MSG_CHANNEL_FAILURE)
                {
                    throw new Exception("Failed to request channel message: ...!");
                }
            }
            finally
            {
                _client.DeregisterMessageHandler(channelReader);
            }
        }

        /// <summary>
        /// Opens the channel.
        /// </summary>
        /// <param name="openMessage">The channel open messages that defines the opening parameters of the channel.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task OpenAsync(ChannelOpen openMessage, CancellationToken cancellationToken)
        {
            bool FilterMessage(MessageEvent message)
            {
                if (message.Message is not IChannelRecipient msg || msg.RecipientChannel != ClientId)
                {
                    return false;
                }

                return message.Type switch
                {
                    MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION
                    or MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE
                        => true,
                    _ => false,
                };
            }

            var channelReader = _client.RegisterMessageHandler(FilterMessage);
            try
            {
                // TODO: We should just accept the channel type, and let the other variables be init properties on this class.
                _receiveWindow = (int)openMessage.InitialWindowSize;
                await _client.WriteMessageAsync(openMessage, cancellationToken).ConfigureAwait(false);

                // Check if this was allowed..
                var message = await channelReader.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (message.Message is not ChannelOpenConfirmation confirmation)
                {
                    throw new Exception("Failed to open channel!");
                }
                ServerId = confirmation.SenderChannel;
                _sendWindow = (int)confirmation.InitialWindowSize;
            }
            finally
            {
                _client.DeregisterMessageHandler(channelReader);
            }
        }

        /// <summary>
        /// Closes the channel.
        /// </summary>
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            try
            {
                // Mark the channel as closed on our end if there wasn't some other related error.
                _close.TrySetResult();

                _cts.Cancel();
                try
                {
                    await _client.WriteMessageAsync(new ChannelClose(ServerId), cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    // The connection might have failed. Let's not throw during a dispose operation.
                }

                try
                {
                    await _backgroundTask.ConfigureAwait(false);
                }
                catch
                {
                    // Errors bubble up to other Public APIs and we want to ignore these errors.
                }
            }
            finally
            {
                _cts.Dispose();
            }
        }

        public async ValueTask DisposeAsync()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await CloseAsync(cts.Token);
        }
    }
}
