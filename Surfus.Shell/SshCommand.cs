using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Surfus.Shell.Exceptions;
using Surfus.Shell.Messages;
using Surfus.Shell.Messages.Channel.Open;
using Surfus.Shell.Messages.Channel.Requests;
using NLog;

namespace Surfus.Shell
{
    public class SshCommand : IDisposable
    {
        private Logger _logger;
        private SshChannel _channel;
        private SshClient _client;
        private bool _isDisposed;
        private SemaphoreSlim _commandSemaphore = new SemaphoreSlim(1, 1);
        private CancellationTokenSource _commandCancellation = new CancellationTokenSource();
        private State _commandState = State.Initial;
        private readonly MemoryStream _memoryStream = new MemoryStream();

        internal SshCommand(SshClient sshClient, SshChannel channel)
        {
            _client = sshClient;
            _logger = LogManager.GetLogger($"{_client.ConnectionInfo.Hostname} {_client.ConnectionInfo.Port}");
            _channel = channel;
            _channel.OnDataReceived += async (buffer, cancellationToken) =>
            {
                await _commandSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

                _memoryStream.Write(buffer, 0, buffer.Length);

                _commandSemaphore.Release();
            };
        }

        public async Task OpenAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _commandCancellation.Token))
            {
                await _commandSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_commandState != State.Initial)
                {
                    throw new Exception("Command request was already attempted.");
                }

                // Errored until success.
                _commandState = State.Errored;

                await _channel.OpenAsync(new ChannelOpenSession(_channel.ClientId, 50000), _client.InternalCancellation.Token).ConfigureAwait(false);

                _commandState = State.Opened;

                _commandSemaphore.Release();
            }
        }

        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _commandCancellation.Token))
            {
                await _commandSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_commandState == State.Opened)
                {
                    await _channel.CloseAsync(linkedCancellation.Token).ConfigureAwait(false);
                }
                _commandState = State.Closed;
                _commandSemaphore.Release();
                Close();
            };
        }

        public void Close()
        {
            if (!_isDisposed)
            {
                if(!_commandCancellation.IsCancellationRequested)
                {
                    _commandCancellation.Cancel(true);
                }
                _isDisposed = true;
                _commandSemaphore.Dispose();
                _commandCancellation.Dispose();
            }
        }

        public void Dispose()
        {
            Close();
        }

        public async Task<string> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            using (var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _commandCancellation.Token))
            {
                await _commandSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

                if (_commandState != State.Opened)
                {
                    throw new Exception("Command request is not opened");
                }

                var executeCloseTaskSource = new TaskCompletionSource<bool>();
                var executeEofTaskSource = new TaskCompletionSource<bool>();

				using (linkedCancellation.Token.Register(() => executeCloseTaskSource?.TrySetCanceled()))
				using (linkedCancellation.Token.Register(() => executeEofTaskSource?.TrySetCanceled()))
				{

					_channel.OnChannelEofReceived = async (message, token) =>
					{
						await _commandSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

						executeEofTaskSource.SetResult(true);

						_commandSemaphore.Release();
					};

					_channel.OnChannelCloseReceived = async (message, token) =>
					{
						await _commandSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);

						executeCloseTaskSource.SetResult(true);

						_commandSemaphore.Release();
					};

					await _channel.RequestAsync(new ChannelRequestExec(_channel.ServerId, true, command), _client.InternalCancellation.Token).ConfigureAwait(false);
					_commandSemaphore.Release();


					await executeEofTaskSource.Task.ConfigureAwait(false);
					await executeCloseTaskSource.Task.ConfigureAwait(false);
				}

                _channel.OnChannelEofReceived = null;
                _channel.OnChannelCloseReceived = null;

                await _commandSemaphore.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
                _commandState = State.Completed;

                using (_memoryStream)
                {
                    _commandSemaphore.Release();
                    return Encoding.UTF8.GetString(_memoryStream.ToArray());
                }
            }
        }

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
