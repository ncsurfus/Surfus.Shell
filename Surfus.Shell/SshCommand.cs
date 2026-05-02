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
    /// The result of an SSH command execution containing stdout and stderr.
    /// </summary>
    public class SshCommandResult
    {
        public string Stdout { get; }
        public string Stderr { get; }

        internal SshCommandResult(string stdout, string stderr)
        {
            Stdout = stdout;
            Stderr = stderr;
        }
    }

    /// <summary>
    /// A command to be sent to the server.
    /// </summary>
    public class SshCommand : IDisposable
    {
        /// <summary>
        /// The channel the command will be sent over.
        /// </summary>
        private readonly SshChannel _channel;

        /// <summary>
        /// The disposed state of the command.
        /// </summary>
        private bool _isDisposed;

        /// <summary>
        /// The state of the command process.
        /// </summary>
        private State _commandState = State.Initial;

        /// <summary>
        /// The buffer to store the received stdout data into.
        /// </summary>
        private readonly MemoryStream _stdoutStream = new MemoryStream();

        /// <summary>
        /// The buffer to store the received stderr data into.
        /// </summary>
        private readonly MemoryStream _stderrStream = new MemoryStream();

        /// <summary>
        /// When true, stderr data is combined into the stdout stream.
        /// </summary>
        public bool CombineStderr { get; set; }

        /// <summary>
        /// Constructs the command to be sent to the server.
        /// </summary>
        /// <param name="channel">The channel to send the command over.</param>
        internal SshCommand(SshChannel channel)
        {
            _channel = channel;
            _channel.OnDataReceived = OnDataReceived;
            _channel.OnExtendedDataReceived = OnExtendedDataReceived;
        }

        /// <summary>
        /// Receives stdout data from the channel.
        /// </summary>
        internal void OnDataReceived(byte[] buffer, int offset, int length)
        {
            _stdoutStream.Write(buffer, offset, length);
        }

        /// <summary>
        /// Receives stderr data from the channel.
        /// </summary>
        internal void OnExtendedDataReceived(byte[] buffer, int offset, int length)
        {
            if (CombineStderr)
                _stdoutStream.Write(buffer, offset, length);
            else
                _stderrStream.Write(buffer, offset, length);
        }

        /// <summary>
        /// Opens the underlying SSH channel and requests to send commands over the channel.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
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
                _channel.Dispose();
                _stdoutStream.Dispose();
                _stderrStream.Dispose();
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
        /// Sends the command to the server and returns the combined output (stdout, or stdout+stderr if combineStderr was set).
        /// </summary>
        /// <param name="command">The command to execute.</param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns>The stdout result of the command (includes stderr if combineStderr is true).</returns>
        public async Task<string> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            var result = await ExecuteWithResultAsync(command, cancellationToken).ConfigureAwait(false);
            return result.Stdout;
        }

        /// <summary>
        /// Sends the command to the server and returns both stdout and stderr.
        /// </summary>
        /// <param name="command">The command to execute.</param>
        /// <param name="cancellationToken">A cancellation token used to cancel the asynchronous method.</param>
        /// <returns>An <see cref="SshCommandResult"/> containing stdout and stderr.</returns>
        public async Task<SshCommandResult> ExecuteWithResultAsync(string command, CancellationToken cancellationToken)
        {
            if (_commandState != State.Opened)
            {
                throw new Exception("Command request is not opened");
            }

            await _channel.RequestAsync(new ChannelRequestExec(_channel.ServerId, true, command), cancellationToken).ConfigureAwait(false);
            await _channel.DrainUntilClosedAsync(cancellationToken).ConfigureAwait(false);

            _commandState = State.Completed;

            var stdout = Encoding.UTF8.GetString(_stdoutStream.ToArray());
            var stderr = Encoding.UTF8.GetString(_stderrStream.ToArray());
            _stdoutStream.Dispose();
            _stderrStream.Dispose();
            return new SshCommandResult(stdout, stderr);
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
