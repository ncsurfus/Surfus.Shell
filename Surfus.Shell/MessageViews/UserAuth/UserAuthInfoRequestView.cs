using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.UserAuth;

/// <summary>
/// Zero-copy view of SSH_MSG_USERAUTH_INFO_REQUEST.
/// Prompts require string allocation since they're passed to user callbacks.
/// </summary>
internal readonly ref struct UserAuthInfoRequestView
{
    public readonly SshUtf8String Name;
    public readonly SshUtf8String Instruction;
    public readonly SshAsciiString Language;
    public readonly uint PromptCount;
    private readonly ReadOnlySpan<byte> _promptData;

    public UserAuthInfoRequestView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        Name = reader.ReadSshUtf8String();
        Instruction = reader.ReadSshUtf8String();
        Language = reader.ReadSshAsciiString();
        PromptCount = reader.ReadUInt32();
        if (PromptCount > 100)
        {
            throw new Exceptions.SshException("Too many prompts");
        }
        _promptData = reader.ReadBytes(reader.Remaining);
    }

    /// <summary>
    /// Reads prompts and echo flags. Allocates strings since they're needed for user interaction.
    /// </summary>
    public void ReadPrompts(Span<string> prompts, Span<bool> echo)
    {
        var reader = new SpanReader(_promptData);
        for (var i = 0; i < PromptCount && i < prompts.Length; i++)
        {
            prompts[i] = reader.ReadUtf8String();
            echo[i] = reader.ReadByte() != 0;
        }
    }
}
