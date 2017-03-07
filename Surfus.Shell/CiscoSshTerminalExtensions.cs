using Surfus.Shell.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    public static class CiscoSshTerminalExtensions
    {
        public static async Task<TerminalMode> GetTerminalModeAsync(this SshTerminal terminal, CancellationToken cancellationToken)
        {
            var initialMode = await terminal.ExpectRegexMatchAsync(@"((?<privileged>\#)|(?<user>)>)\s*", cancellationToken);

            if (initialMode.Groups["privileged"].Success)
            {
                return TerminalMode.Privileged;
            }

            if (initialMode.Groups["user"].Success)
            {
                return TerminalMode.User;
            }

            throw new SshException("Unknown terminal mode");
        }

        public static async Task GetEnableModeAsync(this SshTerminal terminal, string enablePassword, CancellationToken cancellationToken)
        {
            // Get current state. Return if already at privileged.
            var currentMode = await terminal.GetTerminalModeAsync(cancellationToken);
            if(currentMode == TerminalMode.Privileged)
            {
                return;
            }

            // Attempt to get enable prompt
            await terminal.WriteLineAsync("enable", cancellationToken);

            var enablePrompt = await terminal.ExpectRegexMatchAsync(@"(?<passwordPrompt>(Password|password):?\s*)|((?<privileged>\#)|(?<user>)>)\s*", cancellationToken);
            if (enablePrompt.Groups["privileged"].Success)
            {
                return;
            }

            if (enablePrompt.Groups["user"].Success)
            {
                throw new SshException("Server refused to provide enable password prompt");
            }

            if (!enablePrompt.Groups["passwordPrompt"].Success)
            {
                throw new SshException("Unknown Password Prompt");
            }

            // Write enable password
            await terminal.WriteLineAsync(enablePassword, cancellationToken);

            // Check result of new prompt
            var enableResult = await terminal.ExpectRegexMatchAsync(@"(?<passwordPrompt>(Password|password):?\s*)|((?<privileged>\#)|(?<user>)>)\s*", cancellationToken);
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

        public enum TerminalMode
        {
            User,
            Privileged
        }
    }
}
