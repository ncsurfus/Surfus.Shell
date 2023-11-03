using System.Diagnostics;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Surfus.Shell.Tests;

[TestClass]
public class UnitTest1
{

    [AssemblyInitialize]
    public static void AssemblyInitialize(TestContext testContext)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "/usr/bin/docker",
                ArgumentList = { "compose", "up", "-d", "--build" },
                WorkingDirectory = Path.Join(Path.GetDirectoryName(Assembly.GetEntryAssembly()!.Location), "docker"),
            },
        };
        process.Start();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new Exception("Docker failed to start!");
        }
        Thread.Sleep(3000);
    }

    [AssemblyCleanup]
    public static void AssemblyCleanup()
    {
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/usr/bin/docker",
                    ArgumentList = { "compose", "down", "--remove-orphans" },
                    WorkingDirectory = Path.Join(Path.GetDirectoryName(Assembly.GetEntryAssembly()!.Location), "docker"),
                },
            };
            process.Start();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                throw new Exception("Docker failed to stop!");
            }
        }
    }

    [TestMethod]
    public async Task TestPasswordAuthSuccess()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var ssh = new SshClient("127.0.0.1", 40022);
        await ssh.ConnectAsync(cts.Token);
        var auth = await ssh.AuthenticateAsync("testuser", "testpassword", cts.Token);
        Assert.IsTrue(auth);

        var command = await ssh.CreateCommandAsync(cts.Token);
        var response = await command.ExecuteAsync("hostname", cts.Token);
        Assert.AreEqual(response.TrimEnd('\n'), "ssh_ubuntu_2004");
    }

    [TestMethod]
    public async Task TestPasswordAuthFailure()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var ssh = new SshClient("127.0.0.1", 40022);
        await ssh.ConnectAsync(cts.Token);
        var auth = await ssh.AuthenticateAsync("testuser", "badpassword", cts.Token);
        Assert.IsFalse(auth);
    }

    [TestMethod]
    public async Task TestInteractiveAuth()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var ssh = new SshClient("127.0.0.1", 40022);
        await ssh.ConnectAsync(cts.Token);
        var auth = await ssh.AuthenticateAsync("testuser", (m, c) => ValueTask.FromResult("testpassword"), cts.Token);
        Assert.IsTrue(auth);

        var command = await ssh.CreateCommandAsync(cts.Token);
        var response = await command.ExecuteAsync("hostname", cts.Token);
        Assert.AreEqual(response.TrimEnd('\n'), "ssh_ubuntu_2004");
    }

    [TestMethod]
    public async Task TestInteractiveAuthFailure()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var ssh = new SshClient("127.0.0.1", 40022);
        await ssh.ConnectAsync(cts.Token);
        var auth = await ssh.AuthenticateAsync("testuser", (m, c) => ValueTask.FromResult("badpassword"), cts.Token);
        Assert.IsFalse(auth);
    }

    [TestMethod]
    public async Task TestReceiveChannelWindow()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var ssh = new SshClient("127.0.0.1", 40022);
        await ssh.ConnectAsync(cts.Token);
        var auth = await ssh.AuthenticateAsync("testuser", "testpassword", cts.Token);

        var action = "bash -c 'dd if=/dev/random of=testfile bs=1024 count=10240 && cat testfile | base64 && echo DONE'";
        var command = await ssh.CreateCommandAsync(cts.Token);
        var response = await command.ExecuteAsync(action, cts.Token);
        StringAssert.Contains(response, "DONE");
    }

    [TestMethod]
    public async Task TestSendChannelWindow()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var ssh = new SshClient("127.0.0.1", 40022);
        await ssh.ConnectAsync(cts.Token);
        var auth = await ssh.AuthenticateAsync("testuser", "testpassword", cts.Token);

        var terminal = await ssh.CreateTerminalAsync(cts.Token);
        await terminal.WriteLineAsync("cp /dev/stdin myfile.txt", cts.Token);

        // Generate junk data
        var rnd = new Random();
        var totalBytes = 0;
        while (totalBytes < 10_485_760)
        {
            var bytes = new byte[1024];
            rnd.NextBytes(bytes);
            totalBytes += bytes.Length;
            var data = Convert.ToBase64String(bytes);
            await terminal.WriteLineAsync(data, cts.Token);
        }
        await terminal.WriteLineAsync("DONE", cts.Token);
        await terminal.SendEOFAsync(cts.Token);

        var command = await ssh.CreateCommandAsync(cts.Token);
        var response = await command.ExecuteAsync("cat myfile.txt", cts.Token);
        StringAssert.Contains(response, "DONE");
    }

    [TestMethod]
    public async Task TestTerminalRegex()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var ssh = new SshClient("127.0.0.1", 40022);
        await ssh.ConnectAsync(cts.Token);
        var auth = await ssh.AuthenticateAsync("testuser", "testpassword", cts.Token);

        var terminal = await ssh.CreateTerminalAsync(cts.Token);
        await terminal.WriteLineAsync("hostname", cts.Token);

        await terminal.ExpectRegexAsync("ssh_ubuntu_2004\r?\n", cts.Token);
    }

}
