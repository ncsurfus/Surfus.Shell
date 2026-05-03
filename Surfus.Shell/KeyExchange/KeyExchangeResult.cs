using System;

namespace Surfus.Shell.KeyExchange
{
    public record KeyExchangeResult(Memory<byte> H, BigInt K);
}
