﻿using Surfus.Shell.Exceptions;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell.Cisco
{
    public static class CiscoExtensions
    {
        /// <summary>
        /// Attempts to match the prompt with the following [multiline] regex: ^(?<hostname>[^>\#\s]+)((?<privilegedPrompt>>)|(?<userPrompt>\#))\s*$
        /// You can derive the hostname from the hostname group.
        /// User/Privileged mode can be derived from the privilegedPrompt and userPrompt groups.
        /// </summary>
        /// <param name="terminal">The terminal this method extends.</param>
        /// <param name="cancellationToken">A cancellation token to cancel the request.</param>
        /// <returns></returns>
        public static async Task<Match> GetFullPromptAsync(this SshTerminal terminal, CancellationToken cancellationToken)
        {
            await terminal.GetInitialDelimiter(cancellationToken).ConfigureAwait(false);
            var hostname = await terminal.ExpectRegexMatchAsync(@"^\s?(?<fullPrompt>(?<hostname>[^>\#\s]+)((?<privilegedPrompt>>)|(?<userPrompt>\#)))\s*$", RegexOptions.Multiline, cancellationToken).ConfigureAwait(false);
            await terminal.WriteLineAsync("", cancellationToken).ConfigureAwait(false);
            return hostname;
        }

        public static async Task GetIosInitialDelimiter(this SshTerminal terminal, CancellationToken cancellationToken)
        {
            await terminal.WriteLineAsync(@"terminal length 0", cancellationToken).ConfigureAwait(false);
            await terminal.ExpectAsync(@"terminal length 0", cancellationToken).ConfigureAwait(false);
        }

        public static async Task GetAsaInitialDelimiter(this SshTerminal terminal, CancellationToken cancellationToken)
        {
            await terminal.WriteLineAsync(@"terminal pager 0", cancellationToken).ConfigureAwait(false);
            await terminal.ExpectAsync(@"terminal pager 0", cancellationToken).ConfigureAwait(false);
        }

        public static async Task<TerminalMode> GetTerminalModeAsync(this SshTerminal terminal, CancellationToken cancellationToken)
        {
            var initialMode = await terminal.ExpectRegexMatchAsync(@"((?<privileged>\#)|(?<user>)>)\s*", cancellationToken).ConfigureAwait(false);

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
            var currentMode = await terminal.GetTerminalModeAsync(cancellationToken).ConfigureAwait(false);
            if (currentMode == TerminalMode.Privileged)
            {
                return;
            }

            // Attempt to get enable prompt
            await terminal.WriteLineAsync("enable", cancellationToken).ConfigureAwait(false);

            var enablePrompt = await terminal.ExpectRegexMatchAsync(@"(?<passwordPrompt>(Password|password):?\s*)|((?<privileged>\#)|(?<user>)>)\s*", cancellationToken).ConfigureAwait(false);
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

            //Generate new prompt
        }

        public enum TerminalMode
        {
            User,
            Privileged
        }
    }
}