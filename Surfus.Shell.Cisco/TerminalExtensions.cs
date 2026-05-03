using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.Cisco
{
    /// <summary>
    /// Text-oriented convenience methods for SshTerminal, built on top of the stream API.
    /// </summary>
    internal static class TerminalExtensions
    {
        private static readonly byte[] _readBuf = new byte[4096];

        public static async Task<string> ReadAsync(this SshTerminal terminal, CancellationToken cancellationToken)
        {
            var buf = new byte[4096];
            var n = await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false);
            return Encoding.UTF8.GetString(buf, 0, n);
        }

        public static async Task WriteAsync(this SshTerminal terminal, string text, CancellationToken cancellationToken)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            await terminal.StandardInput.WriteAsync(bytes, 0, bytes.Length, cancellationToken).ConfigureAwait(false);
        }

        public static Task WriteLineAsync(this SshTerminal terminal, string text, CancellationToken cancellationToken)
            => terminal.WriteAsync(text + "\n", cancellationToken);

        public static Task WriteLineAsync(this SshTerminal terminal, CancellationToken cancellationToken)
            => terminal.WriteAsync("\n", cancellationToken);

        public static async Task<string> ExpectAsync(this SshTerminal terminal, string plainText, CancellationToken cancellationToken)
        {
            var sb = new StringBuilder();
            var buf = new byte[4096];
            int index;
            while ((index = sb.ToString().IndexOf(plainText)) == -1)
            {
                var n = await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false);
                if (n == 0) break;
                sb.Append(Encoding.UTF8.GetString(buf, 0, n));
            }
            if (index == -1) return sb.ToString();
            index += plainText.Length;
            return sb.ToString().Substring(0, index);
        }

        public static async Task<Match> ExpectRegexMatchAsync(this SshTerminal terminal, string regexText, CancellationToken cancellationToken)
            => await terminal.ExpectRegexMatchAsync(regexText, RegexOptions.None, cancellationToken).ConfigureAwait(false);

        public static async Task<Match> ExpectRegexMatchAsync(this SshTerminal terminal, string regexText, RegexOptions regexOptions, CancellationToken cancellationToken)
        {
            var sb = new StringBuilder();
            var buf = new byte[4096];
            Match match;
            while (!(match = Regex.Match(sb.ToString(), regexText, regexOptions)).Success)
            {
                var n = await terminal.StandardOutput.ReadAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false);
                if (n == 0) break;
                sb.Append(Encoding.UTF8.GetString(buf, 0, n));
            }
            return match;
        }
    }
}
