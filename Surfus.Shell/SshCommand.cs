using System;
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
        internal void OnDataReceived(byte[] buffer)
        {
            _memoryStream.Write(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Opens the underlying SSH channel and requests to send commands over the channel.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task OpenAsync(CancellationToken cancellationToken)
        {
            if (_commandState != State.Initial)
            {
                throw new Exception("Command request was already attempted.");
            }

            // Errored until success.
            _commandState = State.Errored;

            await _channel.OpenAsync(new ChannelOpenSession(_channel.ClientId, 50000), cancellationToken).ConfigureAwait(false);

            _commandState = State.Opened;
        }

        /// <summary>
        /// Closes the command. 
        /// </summary>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns></returns>
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (_commandState == State.Opened)
            {
                await _channel.CloseAsync(cancellationToken).ConfigureAwait(false);
            }
            _commandState = State.Closed;
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
                _memoryStream.Dispose();
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
            if (_commandState != State.Opened)
            {
                throw new Exception("Command request is not opened");
            }

            bool eof = false;
            bool closed = false;

            _channel.OnChannelEofReceived = (message) => { eof = true; };
            _channel.OnChannelCloseReceived = (message) => { closed = true; };

            await _channel.RequestAsync(new ChannelRequestExec(_channel.ServerId, true, command), cancellationToken).ConfigureAwait(false);
            await _client.ReadUntilAsync(() => eof && closed, cancellationToken).ConfigureAwait(false);

            _commandState = State.Completed;

            using (_memoryStream)
            {
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
