using System;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.Agent
{
    public delegate Task<ReadOnlyMemory<byte>> SignerAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken);

    public record SshAgentKey(ReadOnlyMemory<byte> PublicKey, string KeyType, SignerAsync SignPrivateKey, string Comment);
};
