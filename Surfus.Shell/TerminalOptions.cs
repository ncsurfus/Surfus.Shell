namespace Surfus.Shell
{
    /// <summary>
    /// Options for configuring the pseudo-terminal requested during SSH terminal creation.
    /// </summary>
    public class TerminalOptions
    {
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
    }
}
