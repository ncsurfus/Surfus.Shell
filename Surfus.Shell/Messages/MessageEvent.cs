using System;
using System.Buffers;
using System.Threading;

namespace Surfus.Shell.Messages
{
    /// <summary>
    /// Holds the packet buffer and message type. Implements IDisposable to return the buffer to the pool.
    /// The consumer that claims this message is responsible for disposing it.
    /// If unclaimed, the read loop disposes it.
    /// </summary>
    public sealed class MessageEvent : IDisposable
    {
        private byte[]? _pooledBuffer;

        internal MessageEvent(SshPacket packet, byte[]? pooledBuffer = null)
        {
            Packet = packet;
            _pooledBuffer = pooledBuffer;
            TypeId = packet.Reader.ReadByte();
            Type = (MessageType)TypeId;
        }

        /// <summary>
        /// Gets the raw packet.
        /// </summary>
        public SshPacket Packet { get; }

        /// <summary>
        /// Gets the message type code.
        /// </summary>
        public byte TypeId { get; }

        /// <summary>
        /// Gets the message type.
        /// </summary>
        public MessageType Type { get; }

        /// <summary>
        /// Gets the raw payload bytes after the message type byte as a Span.
        /// Only valid while this MessageEvent has not been disposed.
        /// </summary>
        public ReadOnlySpan<byte> Payload
        {
            get
            {
                var bytes = Packet.Reader.Bytes;
                return bytes.Span.Slice(Packet.Reader.Position);
            }
        }

        /// <summary>
        /// Gets the raw message bytes (type byte + payload) as a Memory.
        /// Suitable for capturing data that needs to outlive the event (e.g., exchange hash).
        /// </summary>
        public ReadOnlyMemory<byte> RawMessage => Packet.Reader.Bytes.Slice(Packet.Reader.Position - 1);

        /// <summary>
        /// Returns the packet buffer to the pool. Safe to call multiple times.
        /// </summary>
        public void Dispose()
        {
            var buf = Interlocked.Exchange(ref _pooledBuffer, null);
            if (buf != null)
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
    }
}
