using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages.Channel.Requests;

namespace Surfus.Shell
{
    /// <summary>
    /// An SSH terminal session, exposing stdin/stdout/stderr as streams.
    /// </summary>
    public class SshTerminal : IAsyncDisposable
    {
        private readonly SshChannel _channel;
        private readonly TerminalOptions _options;
        private State _terminalState = State.Initial;

        /// <summary>
        /// Writable stream to send data to the remote terminal.
        /// Close/dispose this stream to send EOF.
        /// </summary>
        public Stream StandardInput => _channel.Stdin;

        /// <summary>
        /// Readable stream of the remote terminal output.
        /// </summary>
        public Stream StandardOutput => _channel.Stdout;

        /// <summary>
        /// Readable stream of the remote terminal stderr.
        /// Typically empty for PTY sessions since the PTY merges streams.
        /// </summary>
        public Stream StandardError => _channel.Stderr;

        /// <summary>
        /// Whether the underlying channel is still open.
        /// </summary>
        public bool IsOpen => _channel.IsOpen;

        /// <summary>
        /// The exit code returned by the remote process, or null if not yet received.
        /// </summary>
        public int? ExitCode => _channel.ExitCode;

        /// <summary>
        /// Wraps an already-opened session channel as a terminal.
        /// Call <see cref="RequestAsync"/> to request the PTY and shell.
        /// </summary>
        public SshTerminal(SshChannel channel, TerminalOptions? options = null)
        {
            _channel = channel;
            _options = options ?? new TerminalOptions();
        }

        /// <summary>
        /// Requests a pseudo-terminal and starts a shell on the server.
        /// Must be called exactly once; throws if called again.
        /// </summary>
        public async Task RequestAsync(CancellationToken cancellationToken)
        {
            if (_terminalState != State.Initial)
            {
                throw new Exception("Terminal request was already attempted.");
            }

            _terminalState = State.Errored;

            await _channel
                .RequestAsync(
                    new ChannelRequestPseudoTerminal(
                        _channel.ServerId,
                        true,
                        _options.TerminalType,
                        _options.Columns,
                        _options.Rows,
                        _options.WidthPixels,
                        _options.HeightPixels,
                        _options.BuildTerminalModes()
                    ),
                    cancellationToken
                )
                .ConfigureAwait(false);
            await _channel.RequestAsync(new ChannelRequestShell(_channel.ServerId, true), cancellationToken).ConfigureAwait(false);

            _terminalState = State.Opened;
        }

        /// <summary>
        /// Notifies the server of a terminal window size change.
        /// </summary>
        public async Task SendWindowChangeAsync(uint columns, uint rows, CancellationToken cancellationToken)
        {
            if (_terminalState != State.Opened)
            {
                throw new Exception("Terminal not opened.");
            }

            await _channel
                .SendMessageAsync(new ChannelRequestWindowChange(_channel.ServerId, columns, rows), cancellationToken)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// Closes the channel if open and disposes underlying resources.
        /// Safe to call multiple times.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            if (_terminalState == State.Opened)
            {
                try
                {
                    await _channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch { }
            }
            _terminalState = State.Closed;
            await _channel.DisposeAsync().ConfigureAwait(false);
        }

        internal enum State
        {
            Initial,
            Opened,
            Closed,
            Errored,
        }
    }
}
