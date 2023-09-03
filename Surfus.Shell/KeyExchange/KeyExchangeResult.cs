using System;

namespace Surfus.Shell.KeyExchange
{
    internal record KeyExchangeResult(Memory<byte> H, BigInt K);
}
