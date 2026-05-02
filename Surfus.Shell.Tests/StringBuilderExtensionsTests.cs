using System.Text;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Tests;

public class StringBuilderExtensionsTests
{
    [Fact]
    public void IndexOf_FindsSubstring()
    {
        var sb = new StringBuilder("hello world");
        Assert.Equal(6, sb.IndexOf("world"));
    }

    [Fact]
    public void IndexOf_ReturnsMinusOneWhenNotFound()
    {
        var sb = new StringBuilder("hello world");
        Assert.Equal(-1, sb.IndexOf("xyz"));
    }

    [Fact]
    public void IndexOf_FindsAtStart()
    {
        var sb = new StringBuilder("hello");
        Assert.Equal(0, sb.IndexOf("hello"));
    }

    [Fact]
    public void IndexOf_FindsAtEnd()
    {
        var sb = new StringBuilder("hello");
        Assert.Equal(4, sb.IndexOf("o"));
    }

    [Fact]
    public void IndexOf_EmptyString_Throws()
    {
        var sb = new StringBuilder("hello");
        Assert.ThrowsAny<Exception>(() => sb.IndexOf(""));
    }

    [Fact]
    public void IndexOf_WithStartIndex()
    {
        var sb = new StringBuilder("abcabc");
        Assert.Equal(3, sb.IndexOf("abc", 1));
    }

    [Fact]
    public void IndexOf_CaseInsensitive()
    {
        var sb = new StringBuilder("Hello World");
        Assert.Equal(0, sb.IndexOf("hello", ignoreCase: true));
    }

    [Fact]
    public void IndexOf_CaseSensitive_NoMatch()
    {
        var sb = new StringBuilder("Hello World");
        Assert.Equal(-1, sb.IndexOf("hello", ignoreCase: false));
    }

    [Fact]
    public void IndexOf_WithStartIndexAndIgnoreCase()
    {
        var sb = new StringBuilder("abcABC");
        Assert.Equal(3, sb.IndexOf("abc", 1, ignoreCase: true));
    }

    [Fact]
    public void IndexOf_SearchLongerThanContent_ReturnsMinusOne()
    {
        var sb = new StringBuilder("hi");
        Assert.Equal(-1, sb.IndexOf("hello"));
    }

    [Fact]
    public void IndexOf_SingleChar()
    {
        var sb = new StringBuilder("abcdef");
        Assert.Equal(3, sb.IndexOf("d"));
    }

    [Fact]
    public void IndexOf_RepeatedPattern_FindsFirst()
    {
        var sb = new StringBuilder("aaaa");
        Assert.Equal(0, sb.IndexOf("aa"));
    }
}
