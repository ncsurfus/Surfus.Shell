using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;

namespace Surfus.Shell
{
    /// <summary>
    /// Executes a command on the remote server, exposing stdin/stdout/stderr as streams.
    /// </summary>
    public class SshCommand : IAsyncDisposable
    {
        private readonly SshChannel _channel;
        private State _commandState = State.Initial;

        /// <summary>
        /// When true, stderr data is interleaved into StandardOutput.
        /// Must be set before calling StartAsync.
        /// </summary>
        public bool CombineStderr { get; init; }

        /// <summary>
        /// Writable stream to send data to the remote process stdin.
        /// Close/dispose this stream to send EOF.
        /// </summary>
        public Stream StandardInput => _channel.Stdin;

        /// <summary>
        /// Readable stream of the remote process stdout.
        /// </summary>
        public Stream StandardOutput => _channel.Stdout;

        /// <summary>
        /// Readable stream of the remote process stderr.
        /// Empty when CombineStderr is true (all data goes to StandardOutput).
        /// </summary>
        public Stream StandardError => _channel.Stderr;

        /// <summary>
        /// The exit code returned by the remote process, or null if not yet received.
        /// </summary>
        public int? ExitCode => _channel.ExitCode;

        internal SshCommand(SshChannel channel)
        {
            _channel = channel;
        }

        internal async Task OpenAsync(CancellationToken cancellationToken)
        {
            if (_commandState != State.Initial)
            {
                throw new Exception("Command request was already attempted.");
            }

            _commandState = State.Errored;
            await _channel.OpenAsync(new ChannelOpenSession(_channel.ClientId, 50000), cancellationToken).ConfigureAwait(false);
            _commandState = State.Opened;
        }

        /// <summary>
        /// Optionally requests a pseudo-terminal before starting the command.
        /// Must be called after OpenAsync and before StartAsync.
        /// </summary>
        public async Task RequestPseudoTerminalAsync(CancellationToken cancellationToken, TerminalOptions? options = null)
        {
            if (_commandState != State.Opened)
            {
                throw new Exception("Command is not opened.");
            }

            var opts = options ?? new TerminalOptions();
            await _channel
                .RequestAsync(
                    new ChannelRequestPseudoTerminal(
                        _channel.ServerId,
                        true,
                        opts.TerminalType,
                        opts.Columns,
                        opts.Rows,
                        opts.WidthPixels,
                        opts.HeightPixels
                    ),
                    cancellationToken
                )
                .ConfigureAwait(false);
        }

        /// <summary>
        /// Starts executing the command. Read from StandardOutput/StandardError and write to StandardInput.
        /// </summary>
        public async Task StartAsync(string command, CancellationToken cancellationToken)
        {
            if (_commandState != State.Opened)
            {
                throw new Exception("Command is not opened.");
            }

            await _channel.RequestAsync(new ChannelRequestExec(_channel.ServerId, true, command), cancellationToken).ConfigureAwait(false);

            _commandState = State.Started;
        }

        public async ValueTask DisposeAsync()
        {
            if (_commandState == State.Opened || _commandState == State.Started)
            {
                try
                {
                    await _channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch { }
            }
            _commandState = State.Closed;
            await _channel.DisposeAsync().ConfigureAwait(false);
        }

        internal enum State
        {
            Initial,
            Opened,
            Started,
            Closed,
            Errored,
        }
    }
}
