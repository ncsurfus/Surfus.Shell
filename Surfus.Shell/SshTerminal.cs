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
        private static Logger _logger = LogManager.GetCurrentClassLogger();
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
            _channel = channel;
            _channel.OnDataReceived = async (buffer, cancellationToken) =>
            {
                await _terminalSemaphore.WaitAsync(cancellationToken);

                if(_terminalReadComplete?.TrySetResult(Encoding.UTF8.GetString(buffer)) != true)
                {
                    _readBuffer.Append(Encoding.UTF8.GetString(buffer));
                }

                _terminalSemaphore.Release();
            };

            _channel.OnChannelCloseReceived = async (close, cancellationToken) =>
            {
                await _terminalSemaphore.WaitAsync(cancellationToken);

                await CloseAsync(cancellationToken);
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
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token);

                if (_terminalState != State.Initial)
                {
                    throw new Exception("Terminal request was already attempted.");
                }

                // Errored until success.
                _terminalState = State.Errored;

                await _channel.OpenAsync(new ChannelOpenSession(_channel.ClientId, 50000), linkedCancellation.Token);
                await _channel.RequestAsync(new ChannelRequestPseudoTerminal(_channel.ServerId, true, "Surfus", 80, 24), linkedCancellation.Token);
                await _channel.RequestAsync(new ChannelRequestShell(_channel.ServerId, true), linkedCancellation.Token);

                _terminalState = State.Opened;

                _terminalSemaphore.Release();
            }
        }

        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token);

                if (_terminalState == State.Opened)
                {
                    await _channel.CloseAsync(linkedCancellation.Token);
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
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token);

                if (_terminalState != State.Opened)
                {
                    throw new Exception("Terminal not opened.");
                }

                await _channel.WriteDataAsync(Encoding.UTF8.GetBytes(text), linkedCancellation.Token);

                _terminalSemaphore.Release();
            }
        }

        public Task WriteLineAsync(string text, CancellationToken cancellationToken)
        {
            return WriteAsync(text + "\n", cancellationToken);
        }

        public async Task<string> ReadAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token);

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
                _terminalSemaphore.Release();
                _terminalReadComplete = new TaskCompletionSource<string>();

                linkedCancellation.Token.Register(() => _terminalReadComplete?.TrySetCanceled());

                return await _terminalReadComplete.Task;
            }
        }

        public async Task<char> ReadCharAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _terminalCancellation.Token))
            {
                await _terminalSemaphore.WaitAsync(linkedCancellation.Token);

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
                _terminalSemaphore.Release();
                _terminalReadComplete = new TaskCompletionSource<string>();

                linkedCancellation.Token.Register(() => _terminalReadComplete?.TrySetCanceled());

                var data = await _terminalReadComplete.Task;

                await _terminalSemaphore.WaitAsync(linkedCancellation.Token);
                if(data.Length > 0)
                {
                    _readBuffer.Append(data, 1, data.Length - 1);
                    var text = data[0];
                    _terminalSemaphore.Release();
                    return text;
                }

                _terminalSemaphore.Release();
                throw new SshException("No Character to Read....");
            }
        }

        public async Task<string> ExpectAsync(string plainText, CancellationToken cancellationToken)
        {
            var buffer = new StringBuilder();
            // Todo: Convert this to use Find and put the remaining data back in the buffer.
            while (!buffer.ToString().Contains(plainText))
            {
                buffer.Append(await ReadCharAsync(cancellationToken));
            }
            return buffer.ToString();
        }

        public Task<string> ExpectRegexAsync(string regexText, CancellationToken cancellationToken)
        {
            return ExpectRegexAsync(regexText, RegexOptions.None, cancellationToken);
        }

        public async Task<string> ExpectRegexAsync(string regexText, RegexOptions regexOptions, CancellationToken cancellationToken)
        {
            var buffer = new StringBuilder();
            // Todo: Convert this to ReadAsync and put the remaining data back in the buffer.
            while (!Regex.Match(buffer.ToString(), regexText, regexOptions).Success)
            {
                buffer.Append(await ReadCharAsync(cancellationToken));
            }
            return buffer.ToString();
        }

        public Task<Match> ExpectRegexMatchAsync(string regexText, CancellationToken cancellationToken)
        {
            return ExpectRegexMatchAsync(regexText, RegexOptions.None, cancellationToken);
        }

        public async Task<Match> ExpectRegexMatchAsync(string regexText, RegexOptions regexOptions, CancellationToken cancellationToken)
        {
            var buffer = new StringBuilder();
            var match = Regex.Match(buffer.ToString(), regexText, regexOptions);

            // Todo: Convert this to ReadAsync and put the remaining data back in the buffer.
            while (!match.Success)
            {
                buffer.Append(await ReadCharAsync(cancellationToken));
                match = Regex.Match(buffer.ToString(), regexText, regexOptions);
            }
            return match;
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
