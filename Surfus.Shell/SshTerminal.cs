﻿using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;
using System.Text.RegularExpressions;
using Surfus.Shell.Extensions;
using Surfus.Shell.Messages.Channel;

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
        private readonly StringBuilder _readBuffer = new StringBuilder();

        /// <summary>
        /// Creates the SSH Terminal.
        /// </summary>
        /// <param name="sshClient">The SSH client the terminal was opened to.</param>
        /// <param name="channel">The channel the terminal was opened for.</param>
        internal SshTerminal(SshClient sshClient, SshChannel channel)
        {
            _client = sshClient;
            _channel = channel;
            _channel.OnDataReceived = OnDataReceived;
            _channel.OnChannelCloseReceived = OnChannelCloseReceived;
        }

        /// <summary>
        /// The state of the channel.
        /// </summary>
        public bool IsOpen => _channel.IsOpen;

        /// <summary>
        /// Returns true if data can be the read from the channel.
        /// </summary>
        public bool DataAvailable => _readBuffer.Length > 0;

        /// <summary>
        /// Do Not Use (Yet).
        /// </summary>
        public Func<string, bool> DataReceivedCallback;

        /// <summary>
        /// The callback if the server disconnects.
        /// </summary>
        public event Action ServerDisconnected;

        /// <summary>
        /// The channel callback for when data can be read.
        /// </summary>
        /// <param name="buffer">The data sent through the channel.</param>
        /// <returns></returns>
        private void OnDataReceived(byte[] buffer, int offset, int length)
        {
            var data = Encoding.UTF8.GetString(buffer, offset, length);

            if (DataReceivedCallback == null)
            {
                _readBuffer.Append(data);
            }
            else if (DataReceivedCallback(data))
            {
                _readBuffer.Append(data);
            }
        }

        /// <summary>
        /// The channel callback for when the channel is closed.
        /// </summary>
        /// <param name="close">The channel close message.</param>
        /// <returns></returns>
        private void OnChannelCloseReceived(ChannelClose close)
        {
            ServerDisconnected?.Invoke();
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
        public async Task<string> ReadAsync(CancellationToken cancellationToken)
        {
            if (_terminalState != State.Opened)
            {
                throw new Exception("Terminal not opened.");
            }

            if (_readBuffer.Length == 0)
            {
                await _client.ReadWhileAsync(() => _readBuffer.Length == 0, cancellationToken).ConfigureAwait(false);
            }
            var text = _readBuffer.ToString();
            _readBuffer.Clear();
            return text;
        }

        /// <summary>
        /// Reads a single character from the server.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>a single character from the server.</returns>
        public async Task<char> ReadCharAsync(CancellationToken cancellationToken)
        {
            if (_terminalState != State.Opened)
            {
                throw new Exception("Terminal not opened.");
            }

            if (_readBuffer.Length == 0)
            {
                await _client.ReadWhileAsync(() => _readBuffer.Length == 0, cancellationToken).ConfigureAwait(false);
            }
            var text = _readBuffer[0];
            _readBuffer.Remove(0, 1);
            return text;
        }

        /// <summary>
        /// Returns once the expected text is received from the server.
        /// </summary>
        /// <param name="plainText">The text to be expected.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>The matching text.</returns>
        public async Task<string> ExpectAsync(string plainText, CancellationToken cancellationToken)
        {
            int index;
            while ((index = _readBuffer.IndexOf(plainText)) == -1)
            {
                var currentBufferSize = _readBuffer.Length;
                await _client.ReadWhileAsync(() => currentBufferSize == _readBuffer.Length, cancellationToken).ConfigureAwait(false);
            }
            index = index + plainText.Length;
            var result = _readBuffer.ToString().Substring(0, index);
            _readBuffer.Remove(0, index);
            return result;
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
            Match regexMatch;
            while (!(regexMatch = Regex.Match(_readBuffer.ToString(), regexText, regexOptions)).Success)
            {
                var currentBufferSize = _readBuffer.Length;
                await _client.ReadWhileAsync(() => currentBufferSize == _readBuffer.Length, cancellationToken).ConfigureAwait(false);
            }
            var index = regexMatch.Index + regexMatch.Length;
            _readBuffer.Remove(0, index);
            return regexMatch;
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
