using Surfus.Shell.Exceptions;
using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.Cisco
{
    public static class CiscoExtensions
    {
        public static async Task<CiscoTerminal> CiscoInitializeAndEnable(this SshTerminal terminal, string enablePassword, CancellationToken cancellationToken)
        {
            // Get the prompt
            var prompt = await terminal.GetPromptAsync(cancellationToken);

            if (prompt.Groups["privileged"].Success)
            {
                await terminal.FixTerminalLength(cancellationToken);
                return new CiscoTerminal
                {
                    Prompt = prompt.Groups["fullPrompt"].Value,
                    Name = prompt.Groups["hostname"].Value,
                    Mode = TerminalMode.Privileged
                };
            }

            await terminal.GetEnableModeAsync(enablePassword, cancellationToken);
            prompt = await terminal.GetPromptAsync(cancellationToken);
            await terminal.FixTerminalLength(cancellationToken);
            return new CiscoTerminal
            {
                Prompt = prompt.Groups["fullPrompt"].Value,
                Name = prompt.Groups["hostname"].Value,
                Mode = TerminalMode.Privileged
            };
        }

        private static async Task<Match> GetPromptAsync(this SshTerminal terminal, CancellationToken cancellationToken)
        {
            Match prompt;
            try
            {
                await terminal.WriteLineAsync("ab cdef", cancellationToken);
                await terminal.ExpectAsync("ab cdef", cancellationToken);
                await terminal.WriteAsync("a bcdef", cancellationToken);
                prompt = await terminal.ExpectRegexMatchAsync(@"^\s?(?<fullPrompt>(?<hostname>[^>\#\s]+)((?<user>>)|(?<privileged>\#)))\s*(?=a bcdef)", RegexOptions.Multiline, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new SshException("Failed to get prompt", ex);
            }

            try
            {
                await terminal.WriteLineAsync(cancellationToken);
                await terminal.ExpectAsync(prompt.Groups["fullPrompt"].Value, cancellationToken);
            }
            catch (Exception ex)
            {
                throw new SshException($"Failed to validate prompt: {prompt.Value}", ex);
            }

            return prompt;
        }

        private static async Task GetEnableModeAsync(this SshTerminal terminal, string enablePassword, CancellationToken cancellationToken)
        {
            // Attempt to get enable prompt
            await terminal.WriteLineAsync("enable", cancellationToken).ConfigureAwait(false);

            var enablePrompt = await terminal.ExpectRegexMatchAsync(@"(?<passwordPrompt>(Password|password):?\s*)|((?<privileged>\#)|(?<user>)>)\s*", cancellationToken).ConfigureAwait(false);

            // Server gave privileged prompt with no password.
            if (enablePrompt.Groups["privileged"].Success)
            {
                return;
            }

            // Server gave user prompt with no password.
            if (enablePrompt.Groups["user"].Success)
            {
                throw new SshException("Server refused to provide enable password prompt");
            }

            // Server gave us something else.
            if (!enablePrompt.Groups["passwordPrompt"].Success)
            {
                throw new SshException("Unknown Password Prompt");
            }

            // Write enable password
            await terminal.WriteLineAsync(enablePassword, cancellationToken).ConfigureAwait(false);

            // Check result of new prompt
            var enableResult = await terminal.ExpectRegexMatchAsync(@"(?<passwordPrompt>(Password|password):?\s*)|((?<privileged>\#)|(?<user>)>)\s*", cancellationToken).ConfigureAwait(false);
            if (enableResult.Groups["privileged"].Success)
            {
                return;
            }

            if (enableResult.Groups["user"].Success)
            {
                throw new SshException("Server rejected enable request and returned to user prompt");
            }

            if (enableResult.Groups["passwordPrompt"].Success)
            {
                throw new SshException("Server rejected enable request and returned to password prompt");
            }
        }

        private static async Task FixTerminalLength(this SshTerminal terminal, CancellationToken cancellationToken)
        {
            await terminal.WriteLineAsync("terminal length 0", cancellationToken);
            await terminal.ExpectAsync("terminal length 0", cancellationToken);
            await terminal.WriteLineAsync("terminal pager 0", cancellationToken);
            await terminal.ExpectAsync("terminal pager 0", cancellationToken);
        }
    }

    public class CiscoTerminal
    {
        public string Prompt { get; set; }
        public string Name { get; set; }
        public TerminalMode Mode { get; set; }
    }

    public enum TerminalMode
    {
        User,
        Privileged
    }
}
