namespace Surfus.Shell
{
    /// <summary>
    /// A single terminal mode setting (RFC 4254 §8): an opcode and a uint32 value.
    /// </summary>
    public readonly record struct TerminalMode(byte Opcode, uint Value)
    {
        /// <summary>ECHO (opcode 53): enable/disable input echo.</summary>
        public static TerminalMode Echo(bool enabled) => new(53, enabled ? 1u : 0u);

        /// <summary>ICRNL (opcode 63): translate CR to NL on input.</summary>
        public static TerminalMode Icrnl(bool enabled) => new(63, enabled ? 1u : 0u);

        /// <summary>ONLCR (opcode 72): translate NL to CR-NL on output.</summary>
        public static TerminalMode Onlcr(bool enabled) => new(72, enabled ? 1u : 0u);
    }
}
