using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;
using NLog;
using System.Text.RegularExpressions;

namespace Surfus.Shell
{
    public class SshTerminal : IDisposable
    {
        private Logger _logger;
        private SemaphoreSlim _terminalSemaphore = new SemaphoreSlim(1, 1);
        private CancellationTokenSource _terminalCancellation = new CancellationTokenSource();
        private State _terminalState = State.Initial;
        private SshChannel _channel;
        private SshClient _client;
        private bool _isDisposed;
        private TaskCompletionSource<string> _terminalReadComplete;

        private readonly StringBuilder _readBuffer = new StringBuilder();

        internal SshTerminal(SshClient sshClient, SshChannel channel)
        {
            _client = sshClient;
            _logger = LogManager.GetLogger($"{_client.ConnectionInfo.Hostname} {_client.ConnectionInfo.Port}");
            _channel = channel;
            _channel.OnDataReceived = async (buffer, cancellationToken) =>
            {
                _logger.Info("Terminal OnDataReceived is waiting for the terminal Semaphore");
                await _terminalSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                _logger.Info("Terminal OnDataReceived has got the terminal Semaphore");
                _logger.Info($"Terminal Data: {Encoding.UTF8.GetString(buffer)}");

                if (_terminalReadComplete?.TrySetResult(Encoding.UTF8.GetString(buffer)) != true)
                {
                    _readBuffer.Append(Encoding.UTF8.GetString(buffer));
                }

                _terminalSemaphore.Release();
                _logger.Info("Terminal OnDataReceived has released the terminal semaphore");
            };

            _channel.OnChannelCloseReceived = async (close, cancellationToken) =>
            {
                await _terminalSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

                await CloseAsync(cancellationToken).ConfigureAwait(false);
                ServerDisconnected?.Invoke();

                _terminalSemaphore.Release();
            };
        }

        public bool IsOpen => _channel.IsOpen;
        public bool DataAvailable => _readBuffer.Length > 0;

        public event Action ServerDisconnected;

        public async Task OpenAsync(CancellationToken cancellationToken)
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

        public async Task WriteAsync(string text, CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                _logger.Info($"WriteAsync is getting Semaphore");
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                _logger.Info($"WriteAsync has got Semaphore");
                if (_terminalState != State.Opened)
                {
                    throw new Exception("Terminal not opened.");
                }
                 _terminalSemaphore.Release();
                _logger.Info($"WriteAsync released Semaphore");
                _logger.Info($"Writing {text}");
                await _channel.WriteDataAsync(Encoding.UTF8.GetBytes(text), linkedCancellation.Token).ConfigureAwait(false);
            }
        }

        public async Task WriteLineAsync(string text, CancellationToken cancellationToken)
        {
            await WriteAsync(text + "\n", cancellationToken).ConfigureAwait(false);
        }

        public async Task WriteLineAsync(CancellationToken cancellationToken)
        {
            await WriteAsync("\n", cancellationToken).ConfigureAwait(false);
        }

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
                    return await _terminalReadComplete.Task.ConfigureAwait(false);
                }
            }
        }

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
                    var text = await _terminalReadComplete.Task.ConfigureAwait(false);
                    await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                    _readBuffer.Insert(0, text.Substring(1, text.Length - 1));
                    _terminalSemaphore.Release();
                    return text[0];
                }
            }
        }

        public async Task<string> ExpectSlowAsync(string plainText, CancellationToken cancellationToken)
        {
            var buffer = new StringBuilder();
            _logger.Info($"ExpectAsync waiting for {plainText}");
            try
            {
                // Todo: Convert this to use Find and put the remaining data back in the buffer.
                while (!buffer.ToString().Contains(plainText))
                {
                    buffer.Append(await ReadCharAsync(cancellationToken).ConfigureAwait(false));
                }
                _logger.Info($"ExpectAsync found {plainText} as {buffer.ToString()}");
                return buffer.ToString();
            }
            catch
            {
                _logger.Error($"Expecting '{plainText}', but buffer contained {buffer.ToString()}");
                throw;
            }
        }

        public async Task<string> ExpectAsync(string plainText, CancellationToken cancellationToken)
        {
            var buffer = new StringBuilder();
            _logger.Info($"ExpectFastAsync waiting for {plainText}");
            try
            {
                var index = -1;
                while ((index = buffer.ToString().IndexOf(plainText)) == -1)
                {
                    buffer.Append(await ReadAsync(cancellationToken).ConfigureAwait(false));
                }
                using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
                {
                    index = index + plainText.Length;
                    var fixedBuffer = buffer.ToString(0, index);
                    var overflow = buffer.ToString(index, buffer.Length - index);
                    await _terminalSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                    _readBuffer.Insert(0, overflow);
                    _logger.Info($"ExpectAsync found {plainText} as {buffer.ToString()}");
                    _terminalSemaphore.Release();
                    return fixedBuffer;
                }
            }
            catch
            {
                _logger.Error($"Expecting '{plainText}', but buffer contained {buffer.ToString()}");
                throw;
            }
        }

        public async Task<string> ExpectRegexAsync(string regexText, CancellationToken cancellationToken)
        {
            return (await ExpectRegexMatchAsync(regexText, RegexOptions.None, cancellationToken).ConfigureAwait(false)).Value;
        }

        public async Task<string> ExpectRegexSlowAsync(string regexText, RegexOptions regexOptions, CancellationToken cancellationToken)
        {
            return (await ExpectRegexMatchAsync(regexText, regexOptions, cancellationToken).ConfigureAwait(false)).Value;
        }

        public async Task<Match> ExpectRegexMatchAsync(string regexText, RegexOptions regexOptions, CancellationToken cancellationToken)
        {
            var buffer = new StringBuilder();
            // Todo: Convert this to ReadAsync and put the remaining data back in the buffer.
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
                _logger.Info($"ExpectAsync found {regexText} as {_readBuffer}");
                _terminalSemaphore.Release();
                return regexMatch;
            }
        }

        public Task<Match> ExpectRegexMatchAsync(string regexText, CancellationToken cancellationToken)
        {
            return ExpectRegexMatchAsync(regexText, RegexOptions.None, cancellationToken);
        }

        public async Task<Match> ExpectRegexMatchSlowAsync(string regexText, RegexOptions regexOptions, CancellationToken cancellationToken)
        {
            var buffer = new StringBuilder();
            var match = Regex.Match(buffer.ToString(), regexText, regexOptions);
            _logger.Info($"ExpectRegexMatchAsync waiting for {regexText}");
            try
            {
                // Todo: Convert this to ReadAsync and put the remaining data back in the buffer.
                while (!match.Success)
                {
                    buffer.Append(await ReadCharAsync(cancellationToken).ConfigureAwait(false));
                    match = Regex.Match(buffer.ToString(), regexText, regexOptions);
                }
                _logger.Info($"ExpectRegexMatchAsync found {regexText} as {buffer.ToString()}");
                return match;
            }
            catch
            {
                _logger.Error($"Expecting regex '{regexText}', but buffer contained {buffer.ToString()}");
                throw;
            }
        }

        public void Close()
        {
            if(!_isDisposed)
            {
                _isDisposed = true;
                _terminalSemaphore.Dispose();
                _terminalCancellation.Dispose();
            }
        }

        public void Dispose()
        {
            Close();
        }

        internal enum State
        {
            Initial,
            Opened,
            Closed,
            Errored
        }
    }
}
