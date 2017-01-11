using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    public static class SshClientStaticThread
    {
        static SemaphoreSlim _internalSync = new SemaphoreSlim(1);
        static List<ClientTask> _clients = new List<ClientTask>();
        static TaskCompletionSource<bool> _updateThread = new TaskCompletionSource<bool>();
        static Thread _internalThread;

        public static async Task AddClientAsync(SshClient client)
        {
            await _internalSync.WaitAsync();
            _clients.Add(new ClientTask { Client = client });

            // Start Task thread if it is null or not alive
            if (_internalThread?.IsAlive != true)
            {
                _internalThread = new Thread(() => { RunTasksAsync().Wait(); });
                _internalThread.Start();
            }

            _updateThread.TrySetResult(true);
            _internalSync.Release();
        }

        static async Task RunTasksAsync()
        {
            int taskCount;

            // Get initial Count and initialize clients
            await _internalSync.WaitAsync();
            InitiailizeNewTasks();
            _internalSync.Release();

            while (taskCount > 0)
            {
                var completedTask = await Task.WhenAny(_clients.Select(x => x.Task).Union(new[] { _updateThread.Task }));

                // Set new count and initialize clients
                await _internalSync.WaitAsync();
                if (completedTask == _updateThread.Task)
                {
                    InitiailizeNewTasks();
                }
                else if (completedTask.Exception != null)
                {
                    Console.WriteLine(completedTask.Exception.ToString());
                    var client = _clients.First(x => x.Task == completedTask).Client;
                    client.ThreadTask.TrySetException(completedTask.Exception);
                    _clients.RemoveAll(x => x.Task == completedTask);
                }
                else
                {
                    var completedClient = _clients.First(x => x.Task == completedTask);
                    completedClient.Task = completedClient.Client.WaitRandomAsync();
                }
                _internalSync.Release();
            }

            void InitiailizeNewTasks()
            {
                taskCount = _clients.Count;
                foreach (var clientTask in _clients)
                {
                    if (clientTask.Task == null)
                    {
                        clientTask.Task = clientTask.Client.WaitRandomAsync();
                    }
                }
            }
        }

        public class ClientTask
        {
            public SshClient Client { get; set; }
            public Task Task { get; set; }
        }
    }
}
