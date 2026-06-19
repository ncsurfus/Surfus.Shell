using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Surfus.Shell
{
    /// <summary>
    /// Options for configuring the pseudo-terminal requested during SSH terminal creation.
    /// </summary>
    public class TerminalOptions
    {
        private const byte OpEcho  = 53;
        private const byte OpIcrnl = 63;
        private const byte OpOnlcr = 72;
        private const byte OpEnd   = 0;

        /// <summary>
        /// The terminal type (e.g. "xterm", "vt100"). Defaults to "xterm".
        /// </summary>
        public string TerminalType { get; set; } = "xterm";

        /// <summary>
        /// Terminal width in columns. Defaults to 80.
        /// </summary>
        public uint Columns { get; set; } = 80;

        /// <summary>
        /// Terminal height in rows. Defaults to 24.
        /// </summary>
        public uint Rows { get; set; } = 24;

        /// <summary>
        /// Terminal width in pixels. Defaults to 0 (unspecified).
        /// </summary>
        public uint WidthPixels { get; set; }

        /// <summary>
        /// Terminal height in pixels. Defaults to 0 (unspecified).
        /// </summary>
        public uint HeightPixels { get; set; }

        /// <summary>
        /// Whether the remote PTY echoes typed input back to stdout (RFC 4254 §8, opcode 53 ECHO).
        /// <c>null</c> (default) leaves the server's default in place.
        /// Set to <c>false</c> to suppress echo — useful for automation where you do not want
        /// every sent command reflected back in the read stream.
        /// </summary>
        public bool? Echo { get; set; }

        /// <summary>
        /// Whether the remote PTY translates <c>\r</c> to <c>\n</c> on input
        /// (RFC 4254 §8, opcode 63 ICRNL).
        /// <c>null</c> (default) leaves the server's default in place.
        /// </summary>
        public bool? InputCarriageReturnTranslation { get; set; }

        /// <summary>
        /// Whether the remote PTY translates <c>\n</c> to <c>\r\n</c> on output
        /// (RFC 4254 §8, opcode 72 ONLCR).
        /// <c>null</c> (default) leaves the server's default in place.
        /// </summary>
        public bool? OutputNewlineTranslation { get; set; }

        /// <summary>
        /// Explicit list of terminal modes to encode in the pty-req message (RFC 4254 §8).
        /// When set, the <see cref="Echo"/>, <see cref="InputCarriageReturnTranslation"/>,
        /// and <see cref="OutputNewlineTranslation"/> properties are ignored.
        /// Use for opcodes not exposed as typed properties.
        /// </summary>
        public IReadOnlyList<TerminalMode>? RawTerminalModes { get; set; }

        /// <summary>
        /// Returns the terminal modes bytes to embed in the <c>pty-req</c> message.
        /// </summary>
        internal ReadOnlyMemory<byte> BuildTerminalModes()
        {
            if (RawTerminalModes != null)
                return Encode(RawTerminalModes);

            var modes = new List<TerminalMode>(3);
            if (Echo.HasValue)
                modes.Add(new TerminalMode(OpEcho, Echo.Value ? 1u : 0u));
            if (InputCarriageReturnTranslation.HasValue)
                modes.Add(new TerminalMode(OpIcrnl, InputCarriageReturnTranslation.Value ? 1u : 0u));
            if (OutputNewlineTranslation.HasValue)
                modes.Add(new TerminalMode(OpOnlcr, OutputNewlineTranslation.Value ? 1u : 0u));

            if (modes.Count == 0)
                return ReadOnlyMemory<byte>.Empty;

            return Encode(modes);
        }

        private static ReadOnlyMemory<byte> Encode(IReadOnlyList<TerminalMode> modes)
        {
            if (modes.Count == 0)
                return ReadOnlyMemory<byte>.Empty;

            var buf = new byte[modes.Count * 5 + 1];
            var pos = 0;
            foreach (var mode in modes)
            {
                buf[pos++] = mode.Opcode;
                BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(pos), mode.Value);
                pos += 4;
            }
            buf[pos] = 0; // TTY_OP_END
            return buf;
        }
    }
}
