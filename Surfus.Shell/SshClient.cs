using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    public class SshClient
    {
        public TaskCompletionSource<bool> ThreadTask = new TaskCompletionSource<bool>();

        public Random _randomTest = new Random(DateTime.Today.Millisecond);
        public string Hostname { get; }
        public uint Port { get; }

        public SshClient(string hostname) : this(hostname, 22)
        {
        }

        public SshClient(string hostname, uint port)
        {
            Hostname = hostname;
            Port = port;
        }

        public async Task StartRandomAsync()
        {
            await SshClientStaticThread.AddClientAsync(this);
            await ThreadTask.Task;
        }

        internal async Task WaitRandomAsync()
        {
            var random = _randomTest.Next(1, 4);
            Console.WriteLine($"{Hostname}: {random}");
            if(random == 2)
            {
                throw new Exception("Crashed!");
            }
        }
    }
}
