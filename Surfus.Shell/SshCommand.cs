﻿using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;

namespace Surfus.Shell
{
    /// <summary>
    /// A command to be sent to the server.
    /// </summary>
    public class SshCommand : IDisposable
    {
        /// <summary>
        /// The channel the command will be sent over.
        /// </summary>
        private SshChannel _channel;

        /// <summary>
        /// The client the command will be sent to.
        /// </summary>
        private SshClient _client;

        /// <summary>
        /// The disposed state of the command.
        /// </summary>
        private bool _isDisposed;
        
        /// <summary>
        /// Provides coordination between the async methods.
        /// </summary>
        private SemaphoreSlim _commandSemaphore = new SemaphoreSlim(1, 1);

        /// <summary>
        /// The state of the command process.
        /// </summary>
        private State _commandState = State.Initial;

        /// <summary>
        /// The buffer to store the received command data into.
        /// </summary>
        private readonly MemoryStream _memoryStream = new MemoryStream();

        /// <summary>
        /// Constructs the command to be sent to the server.
        /// </summary>
        /// <param name="sshClient">The client to send the command to.</param>
        /// <param name="channel">The channel to send the command over.</param>
        internal SshCommand(SshClient sshClient, SshChannel channel)
        {
            _client = sshClient;
            _channel = channel;
            _channel.OnDataReceived = OnDataReceived;
        }

        /// <summary>
        /// Receives data from the channel and places it into the buffer.
        /// </summary>
        /// <param name="buffer">The received data.</param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task OnDataReceived(byte[] buffer, CancellationToken cancellationToken)
        {
            await _commandSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            _memoryStream.Write(buffer, 0, buffer.Length);

            _commandSemaphore.Release();
        }

        /// <summary>
        /// Opens the underlying SSH channel and requests to send commands over the channel.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task OpenAsync(CancellationToken cancellationToken)
        {
            await _commandSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_commandState != State.Initial)
            {
                throw new Exception("Command request was already attempted.");
            }

            // Errored until success.
            _commandState = State.Errored;

            await _channel.OpenAsync(new ChannelOpenSession(_channel.ClientId, 50000), cancellationToken).ConfigureAwait(false);

            _commandState = State.Opened;

            _commandSemaphore.Release();
        }

        /// <summary>
        /// Closes the command. 
        /// </summary>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            await _commandSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_commandState == State.Opened)
            {
                await _channel.CloseAsync(cancellationToken).ConfigureAwait(false);
            }
            _commandState = State.Closed;
            _commandSemaphore.Release();
            Close();
        }

        /// <summary>
        /// Closes the command.
        /// </summary>
        public void Close()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;
                _commandSemaphore.Dispose();
            }
        }

        /// <summary>
        /// Disposes the command.
        /// </summary>
        public void Dispose()
        {
            Close();
        }

        /// <summary>
        /// Sends the command to the server.
        /// </summary>
        /// <param name="command"></param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns>The result of the command.</returns>
        public async Task<string> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            await _commandSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_commandState != State.Opened)
            {
                throw new Exception("Command request is not opened");
            }

            var executeCloseTaskSource = new TaskCompletionSource<bool>();
            var executeEofTaskSource = new TaskCompletionSource<bool>();

            using (cancellationToken.Register(() => executeCloseTaskSource?.TrySetCanceled()))
            using (cancellationToken.Register(() => executeEofTaskSource?.TrySetCanceled()))
            {
                _channel.OnChannelEofReceived = async (message, token) =>
                {
                    await _commandSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

                    executeEofTaskSource.SetResult(true);

                    _commandSemaphore.Release();
                };

                _channel.OnChannelCloseReceived = async (message, token) =>
                {
                    await _commandSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

                    executeCloseTaskSource.SetResult(true);

                    _commandSemaphore.Release();
                };

                await _client.ReadUntilAsync(_channel.RequestAsync(new ChannelRequestExec(_channel.ServerId, true, command), cancellationToken), cancellationToken).ConfigureAwait(false);
                _commandSemaphore.Release();


                await _client.ReadUntilAsync(executeEofTaskSource.Task, cancellationToken).ConfigureAwait(false);
                await _client.ReadUntilAsync(executeCloseTaskSource.Task, cancellationToken).ConfigureAwait(false);
            }

            _channel.OnChannelEofReceived = null;
            _channel.OnChannelCloseReceived = null;

            await _commandSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            _commandState = State.Completed;

            using (_memoryStream)
            {
                _commandSemaphore.Release();
                return Encoding.UTF8.GetString(_memoryStream.ToArray());
            }
        }

        /// <summary>
        /// The state of the command process.
        /// </summary>
        internal enum State
        {
            Initial,
            Opened,
            Completed,
            Closed,
            Errored
        }
    }
}
