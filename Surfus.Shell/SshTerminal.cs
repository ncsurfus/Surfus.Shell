using System;
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
        /// Used to coordinate access within the Terminal.
        /// </summary>
        private SemaphoreSlim _terminalSemaphore = new SemaphoreSlim(1, 1);

        /// <summary>
        /// A cancellation token source used to cancel tasks within the terminal.
        /// </summary>
        private CancellationTokenSource _terminalCancellation = new CancellationTokenSource();

        /// <summary>
        /// The state of the terminal.
        /// </summary>
        private State _terminalState = State.Initial;

        /// <summary>
        /// The SshChannel the terminal was opened over.
        /// </summary>
        private SshChannel _channel;

        /// <summary>
        /// The SshClient the terminal was opened to.
        /// </summary>
        private SshClient _client;

        /// <summary>
        /// The disposed state of the terminal.
        /// </summary>
        private bool _isDisposed;

        /// <summary>
        /// The TaskCompletionSource for when the terminal has completed a reading operaiton.
        /// </summary>
        private TaskCompletionSource<string> _terminalReadComplete;

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
        /// The callback if the server disconnects.
        /// </summary>
        public event Action ServerDisconnected;

        /// <summary>
        /// The channel callback for when data can be read.
        /// </summary>
        /// <param name="buffer">The data sent through the channel.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        private async Task OnDataReceived (byte[] buffer, CancellationToken cancellationToken)
        {
            await _terminalSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if(_terminalReadComplete == null || _terminalReadComplete?.Task.IsCompleted == true)
            {
                _readBuffer.Append(Encoding.UTF8.GetString(buffer));
            }
            else
            {
                _terminalReadComplete.SetResult(Encoding.UTF8.GetString(buffer));
            }

            _terminalSemaphore.Release();
        }

        /// <summary>
        /// The channel callback for when the channel is closed.
        /// </summary>
        /// <param name="close">The channel close message.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        private async Task OnChannelCloseReceived(ChannelClose close, CancellationToken cancellationToken)
        {
            await _terminalSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            await CloseAsync(cancellationToken).ConfigureAwait(false);
            ServerDisconnected?.Invoke();

            _terminalSemaphore.Release();
        }

        /// <summary>
        /// Opens the channel and requests a terminal.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        internal async Task OpenAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_terminalState != State.Initial)
                {
                    throw new Exception("Terminal request was already attempted.");
                }

                // Errored until success.
                _terminalState = State.Errored;

                await _channel.OpenAsync(new ChannelOpenSession(_channel.ClientId, 50000), linkedCancellation.Token).ConfigureAwait(false);
                await _channel.RequestAsync(new ChannelRequestPseudoTerminal(_channel.ServerId, true, "Surfus", 80, 24), linkedCancellation.Token).ConfigureAwait(false);
                await _channel.RequestAsync(new ChannelRequestShell(_channel.ServerId, true), linkedCancellation.Token).ConfigureAwait(false);

                _terminalState = State.Opened;

                _terminalSemaphore.Release();
            }
        }

        /// <summary>
        /// Closes the channel.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_terminalState == State.Opened)
                {
                    await _channel.CloseAsync(linkedCancellation.Token).ConfigureAwait(false);
                }
                _terminalState = State.Closed;
                _terminalSemaphore.Release();
                Close();
            };
        }

        /// <summary>
        /// Write data to the server.
        /// </summary>
        /// <param name="text">The text to sent to the server.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns></returns>
        public async Task WriteAsync(string text, CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                if (_terminalState != State.Opened)
                {
                    throw new Exception("Terminal not opened.");
                }
                 _terminalSemaphore.Release();
                await _channel.WriteDataAsync(Encoding.UTF8.GetBytes(text), linkedCancellation.Token).ConfigureAwait(false);
            }
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
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_terminalState != State.Opened)
                {
                    throw new Exception("Terminal not opened.");
                }

                if (_readBuffer.Length > 0)
                {
                    var text = _readBuffer.ToString();
                    _readBuffer.Clear();
                    _terminalSemaphore.Release();
                    return text;
                }
                _terminalReadComplete = new TaskCompletionSource<string>();

                using (linkedCancellation.Token.Register(() => _terminalReadComplete?.TrySetCanceled()))
                {
                    _terminalSemaphore.Release();
                    return await _client.ReadUntilAsync(_terminalReadComplete.Task, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// Reads a single character from the server.
        /// </summary>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>a single character from the server.</returns>
        public async Task<char> ReadCharAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_terminalState != State.Opened)
                {
                    throw new Exception("Terminal not opened.");
                }

                if (_readBuffer.Length > 0)
                {
                    var text = _readBuffer[0];
                    _readBuffer.Remove(0, 1);
                    _terminalSemaphore.Release();
                    return text;
                }
                _terminalReadComplete = new TaskCompletionSource<string>();
                _terminalSemaphore.Release();

                using (linkedCancellation.Token.Register(() => _terminalReadComplete?.TrySetCanceled()))
                {
                    var text = await _client.ReadUntilAsync(_terminalReadComplete.Task, cancellationToken).ConfigureAwait(false);
                    await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                    _readBuffer.Insert(0, text.Substring(1, text.Length - 1));
                    _terminalSemaphore.Release();
                    return text[0];
                }
            }
        }

        /// <summary>
        /// Returns once the expected text is received from the server.
        /// </summary>
        /// <param name="plainText">The text to be expected.</param>
        /// <param name="cancellationToken">A cancellationToken used to cancel the asynchronous method.</param>
        /// <returns>The matching text.</returns>
        public async Task<string> ExpectAsync(string plainText, CancellationToken cancellationToken)
        {
            var buffer = new StringBuilder();
            try
            {
                var index = -1;
                while ((index = buffer.IndexOf(plainText)) == -1)
                {
                    buffer.Append(await ReadAsync(cancellationToken).ConfigureAwait(false));
                    await Task.Delay(100).ConfigureAwait(false);
                }
                using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
                {
                    index = index + plainText.Length;
                    var builderString = buffer.ToString();
                    var fixedBuffer = builderString.Substring(0, index);
                    var overflow = builderString.Substring(index, buffer.Length - index);
                    await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                    _readBuffer.Insert(0, overflow);
                    _terminalSemaphore.Release();
                    return fixedBuffer;
                }
            }
            catch
            {
                throw;
            }
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
            var buffer = new StringBuilder();

            Match regexMatch = null;
            while (!(regexMatch = Regex.Match(buffer.ToString(), regexText, regexOptions)).Success)
            {
                buffer.Append(await ReadAsync(cancellationToken).ConfigureAwait(false));
            }
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                var index = regexMatch.Index + regexMatch.Length;
                var fixedBuffer = buffer.ToString(0, index);
                var overflow = buffer.ToString(index, buffer.Length - index);
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                _readBuffer.Insert(0, overflow);
                _terminalSemaphore.Release();
                return regexMatch;
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
        /// Closes the terminal.
        /// </summary>
        public void Close()
        {
            if(!_isDisposed)
            {
                _isDisposed = true;
                _terminalSemaphore.Dispose();
                _terminalCancellation.Dispose();
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
