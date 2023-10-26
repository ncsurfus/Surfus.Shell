using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;
using System.Text.RegularExpressions;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.Channel;
using System.IO;

namespace Surfus.Shell
{
    /// <summary>
    /// An SSH Terminal
    /// </summary>
    public class SshTerminal : IDisposable
    {
        /// <summary>
        /// The state of the terminal.
        /// </summary>
        private State _terminalState = State.Initial;

        /// <summary>
        /// The SshChannel the terminal was opened over.
        /// </summary>
        private readonly SshChannel _channel;

        /// <summary>
        /// The SshClient the terminal was opened to.
        /// </summary>
        private readonly SshClient _client;

        /// <summary>
        /// The disposed state of the terminal.
        /// </summary>
        private bool _isDisposed;

        /// <summary>
        /// The read buffer.
        /// </summary>
        private Memory<byte> _buffer = Memory<byte>.Empty;

        /// <summary>
        /// Creates the SSH Terminal.
        /// </summary>
        /// <param name="sshClient">The SSH client the terminal was opened to.</param>
        /// <param name="channel">The channel the terminal was opened for.</param>
        internal SshTerminal(SshClient sshClient, SshChannel channel)
        {
            _client = sshClient;
            _channel = channel;
        }

        /// <summary>
        /// Opens the channel and requests a terminal.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task OpenAsync(CancellationToken cancellationToken)
        {
            if (_terminalState != State.Initial)
            {
                throw new Exception("Terminal request was already attempted.");
            }

            // Errored until success.
            _terminalState = State.Errored;

            await _channel.OpenAsync(new ChannelOpenSession(_channel.ClientId, 50000), cancellationToken).ConfigureAwait(false);
            await _channel
                .RequestAsync(new ChannelRequestPseudoTerminal(_channel.ServerId, true, "vt100", 80, 24), cancellationToken)
                .ConfigureAwait(false);
            await _channel.RequestAsync(new ChannelRequestShell(_channel.ServerId, true), cancellationToken).ConfigureAwait(false);

            _terminalState = State.Opened;
        }

        /// <summary>
        /// Closes the channel.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (_terminalState == State.Opened)
            {
                await _channel.CloseAsync(cancellationToken).ConfigureAwait(false);
            }
            _terminalState = State.Closed;
            Close();
        }

        /// <summary>
        /// Write data to the server.
        /// </summary>
        /// <param name="text">The text to sent to the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        public async Task WriteAsync(string text, CancellationToken cancellationToken)
        {
            if (_terminalState != State.Opened)
            {
                throw new Exception("Terminal not opened.");
            }
            await _channel.WriteDataAsync(Encoding.UTF8.GetBytes(text), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes text and a newline to the server.
        /// </summary>
        /// <param name="text">The text to send.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        public async Task WriteLineAsync(string text, CancellationToken cancellationToken)
        {
            await WriteAsync(text + "\n", cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes a newline to the server.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        public async Task WriteLineAsync(CancellationToken cancellationToken)
        {
            await WriteAsync("\n", cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads text from the server.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Text from the server.</returns>
        public async Task<Memory<byte>> ReadBytesAsync(CancellationToken cancellationToken)
        {
            if (_terminalState != State.Opened)
            {
                throw new Exception("Terminal not opened.");
            }

            if (!_buffer.IsEmpty)
            {
                var bufferData = _buffer;
                _buffer = Memory<byte>.Empty;
                return bufferData;
            }

            return await _channel.ReadDataAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads text from the server.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>Text from the server.</returns>
        public async Task<string> ReadAsync(CancellationToken cancellationToken)
        {
            if (_terminalState != State.Opened)
            {
                throw new Exception("Terminal not opened.");
            }

            if (!_buffer.IsEmpty)
            {
                var bufferData = _buffer;
                _buffer = Memory<byte>.Empty;
                return Encoding.UTF8.GetString(bufferData.Span);
            }

            var data = await _channel.ReadDataAsync(cancellationToken).ConfigureAwait(false);
            return Encoding.UTF8.GetString(data.Span);
        }

        /// <summary>
        /// Returns once the expected text is received from the server.
        /// </summary>
        /// <param name="plainText">The text to be expected.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>The matching text.</returns>
        public async Task<string> ExpectAsync(string plainText, CancellationToken cancellationToken)
        {
            var matchBytes = Encoding.UTF8.GetBytes(plainText);

            // Check if the match is already in the buffer.
            int index;
            if ((index = _buffer.Span.IndexOf(matchBytes)) != -1)
            {
                _buffer = _buffer.Slice(0, index + matchBytes.Length);
                return Encoding.UTF8.GetString(_buffer.Span.Slice(index, matchBytes.Length));
            }

            // Write data into a memory stream. The code must ensure that any data ends up in the _buffer.
            // In the event of a Cancellation, all data should be in _buffer, so the caller could further
            // get the data.
            using var memory = new MemoryStream();
            memory.Write(_buffer.Span);
            while ((index = _buffer.Span.IndexOf(matchBytes)) != -1)
            {
                var newData = await _channel.ReadDataAsync(cancellationToken).ConfigureAwait(false);
                memory.Write(newData.Span);
                memory.TryGetBuffer(out var bufferSegment);
                _buffer = bufferSegment.AsMemory();
            }
            var data = _buffer.Slice(0, index + matchBytes.Length);
            _buffer = _buffer.Slice(index + matchBytes.Length);
            return Encoding.UTF8.GetString(data.Span);
        }

        /// <summary>
        /// Expects text that matches a regex expression from the server.
        /// </summary>
        /// <param name="regexText">The regex expression.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>The matching text.</returns>
        public async Task<string> ExpectRegexAsync(string regexText, CancellationToken cancellationToken)
        {
            return (await ExpectRegexMatchAsync(regexText, RegexOptions.None, cancellationToken).ConfigureAwait(false)).Value;
        }

        /// <summary>
        /// Expects text that matches a regex expression from the server.
        /// </summary>
        /// <param name="regexText">The regex expression.</param>
        /// <param name="regexOptions">The regex options.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>The regex match.</returns>
        public async Task<Match> ExpectRegexMatchAsync(string regexText, RegexOptions regexOptions, CancellationToken cancellationToken)
        {
            var builder = new StringBuilder();
            builder.Append(Encoding.UTF8.GetString(_buffer.Span));

            // Check if the match is already in the buffer.
            try
            {
                Match regexMatch;
                while (!(regexMatch = Regex.Match(builder.ToString(), regexText, regexOptions)).Success)
                {
                    var newData = await _channel.ReadDataAsync(cancellationToken).ConfigureAwait(false);
                    builder.Append(Encoding.UTF8.GetString(newData.Span));
                }
                var index = regexMatch.Index + regexMatch.Length;
                _buffer = Encoding.UTF8.GetBytes(builder.ToString(index, builder.Length - index));
                return regexMatch;
            }
            catch
            {
                _buffer = Encoding.UTF8.GetBytes(builder.ToString());
                throw;
            }
        }

        /// <summary>
        /// Expects text that matches a regex expression from the server.
        /// </summary>
        /// <param name="regexText">The regex expression.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>The regex match.</returns>
        public Task<Match> ExpectRegexMatchAsync(string regexText, CancellationToken cancellationToken)
        {
            return ExpectRegexMatchAsync(regexText, RegexOptions.None, cancellationToken);
        }

        /// <summary>
        /// Closes the SshClient
        /// </summary>
        public async Task SendEOFAsync(CancellationToken cancellationToken)
        {
            await _client.WriteMessageAsync(new ChannelEof(_channel.ServerId), cancellationToken);
        }

        /// <summary>
        /// Closes the terminal.
        /// </summary>
        public void Close()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;
            }
        }

        /// <summary>
        /// Disposes the terminal.
        /// </summary>
        public void Dispose()
        {
            Close();
        }

        /// <summary>
        /// The states of the terminal.
        /// </summary>
        internal enum State
        {
            Initial,
            Opened,
            Closed,
            Errored
        }
    }
}
