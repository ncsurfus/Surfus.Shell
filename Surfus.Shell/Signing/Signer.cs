using System;

namespace Surfus.Shell.Signing
{
    public abstract class Signer
    {
        public abstract string Name { get; }
        public abstract bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
        public abstract int KeySize { get; }
    }
}
