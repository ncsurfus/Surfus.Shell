using System;
using Surfus.Shell;

namespace Surfus.Shell.MessageViews.UserAuth;

/// <summary>
/// Zero-copy view of SSH_MSG_USERAUTH_BANNER.
/// </summary>
internal readonly ref struct UserAuthBannerView
{
    public readonly SshUtf8String Message;
    public readonly SshAsciiString LanguageTag;

    public UserAuthBannerView(ReadOnlySpan<byte> payload)
    {
        var reader = new SpanReader(payload);
        Message = reader.ReadSshUtf8String();
        LanguageTag = reader.ReadSshAsciiString();
    }
}
