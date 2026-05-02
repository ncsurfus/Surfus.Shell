using System.Numerics;
using System.Text;
using Surfus.Shell;
using Surfus.Shell.Extensions;

namespace Surfus.Shell.Tests;

public class ByteReaderTests
{
    [Fact]
    public void ReadByte_ReturnsByteAndAdvances()
    {
        var reader = new ByteReader([0xAB, 0xCD]);
        Assert.Equal(0xAB, reader.ReadByte());
        Assert.Equal(1, reader.Position);
        Assert.Equal(0xCD, reader.ReadByte());
    }

    [Theory]
    [InlineData(true, 1)]
    [InlineData(false, 0)]
    public void ReadBoolean_ReturnsCorrectValue(bool expected, byte input)
    {
        var reader = new ByteReader([input]);
        Assert.Equal(expected, reader.ReadBoolean());
    }

    [Fact]
    public void ReadUInt32_BigEndian()
    {
        // 0x01020304 = 16909060
        var reader = new ByteReader([0x01, 0x02, 0x03, 0x04]);
        Assert.Equal(0x01020304u, reader.ReadUInt32());
        Assert.Equal(4, reader.Position);
    }

    [Fact]
    public void ReadUInt32_Zero()
    {
        var reader = new ByteReader([0, 0, 0, 0]);
        Assert.Equal(0u, reader.ReadUInt32());
    }

    [Fact]
    public void ReadUInt32_MaxValue()
    {
        var reader = new ByteReader([0xFF, 0xFF, 0xFF, 0xFF]);
        Assert.Equal(uint.MaxValue, reader.ReadUInt32());
    }

    [Fact]
    public void ReadUInt32_Static_ReadsAtIndex()
    {
        byte[] buffer = [0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        Assert.Equal(0x01020304u, ByteReader.ReadUInt32(buffer, 2));
    }

    [Fact]
    public void ReadString_ReturnsUtf8String()
    {
        var text = "hello";
        var textBytes = Encoding.UTF8.GetBytes(text);
        var buffer = new byte[4 + textBytes.Length];
        WriteUInt32BigEndian(buffer, 0, (uint)textBytes.Length);
        Array.Copy(textBytes, 0, buffer, 4, textBytes.Length);

        var reader = new ByteReader(buffer);
        Assert.Equal("hello", reader.ReadString());
    }

    [Fact]
    public void ReadString_ZeroLength_ReturnsNull()
    {
        var buffer = new byte[4]; // all zeros
        var reader = new ByteReader(buffer);
        Assert.Null(reader.ReadString());
    }

    [Fact]
    public void ReadAsciiString_ReturnsAsciiString()
    {
        var text = "test";
        var textBytes = Encoding.ASCII.GetBytes(text);
        var buffer = new byte[4 + textBytes.Length];
        WriteUInt32BigEndian(buffer, 0, (uint)textBytes.Length);
        Array.Copy(textBytes, 0, buffer, 4, textBytes.Length);

        var reader = new ByteReader(buffer);
        Assert.Equal("test", reader.ReadAsciiString());
    }

    [Fact]
    public void ReadBinaryString_ReturnsByteArray()
    {
        byte[] data = [0xDE, 0xAD, 0xBE, 0xEF];
        var buffer = new byte[4 + data.Length];
        WriteUInt32BigEndian(buffer, 0, (uint)data.Length);
        Array.Copy(data, 0, buffer, 4, data.Length);

        var reader = new ByteReader(buffer);
        Assert.Equal(data, reader.ReadBinaryString());
    }

    [Fact]
    public void ReadNameList_ParsesCommaSeparated()
    {
        var text = "aes256-ctr,aes128-ctr";
        var textBytes = Encoding.UTF8.GetBytes(text);
        var buffer = new byte[4 + textBytes.Length];
        WriteUInt32BigEndian(buffer, 0, (uint)textBytes.Length);
        Array.Copy(textBytes, 0, buffer, 4, textBytes.Length);

        var reader = new ByteReader(buffer);
        var nameList = reader.ReadNameList();
        Assert.Equal(["aes256-ctr", "aes128-ctr"], nameList.Names);
    }

    [Fact]
    public void Read_ReturnsCorrectSlice()
    {
        byte[] data = [1, 2, 3, 4, 5];
        var reader = new ByteReader(data);
        var result = reader.Read(3);
        Assert.Equal(new byte[] { 1, 2, 3 }, result);
        Assert.Equal(3, reader.Position);
    }

    [Fact]
    public void ReadBigInteger_PositiveValue()
    {
        // BigInteger 256 in SSH wire format: length=2, bytes=[0x01, 0x00] (big-endian)
        byte[] buffer = [0x00, 0x00, 0x00, 0x02, 0x01, 0x00];
        var reader = new ByteReader(buffer);
        var bigInt = reader.ReadBigInteger();
        Assert.Equal(new BigInteger(256), bigInt.BigInteger);
    }

    [Fact]
    public void ReadRsaParameter_SkipsLeadingZero()
    {
        // RSA parameter with leading zero byte: length=3, bytes=[0x00, 0x01, 0x02]
        byte[] buffer = [0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x02];
        var reader = new ByteReader(buffer);
        var result = reader.ReadRsaParameter();
        Assert.Equal(new byte[] { 0x01, 0x02 }, result);
    }

    [Fact]
    public void Constructor_WithIndex_StartsAtCorrectPosition()
    {
        byte[] data = [0x00, 0x00, 0xAB];
        var reader = new ByteReader(data, 2);
        Assert.Equal(0xAB, reader.ReadByte());
    }

    private static void WriteUInt32BigEndian(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)value;
    }
}

public class ByteWriterTests
{
    [Fact]
    public void WriteByte_WritesAndAdvances()
    {
        var writer = new ByteWriter(2);
        writer.WriteByte(0xAB);
        Assert.Equal(0xAB, writer.Bytes[0]);
        Assert.Equal(1, writer.Position);
    }

    [Fact]
    public void WriteUint_BigEndian()
    {
        var writer = new ByteWriter(4);
        writer.WriteUint(0x01020304);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, writer.Bytes);
    }

    [Fact]
    public void WriteUint_Static_WritesAtPosition()
    {
        var buffer = new byte[6];
        ByteWriter.WriteUint(buffer, 2, 0x01020304);
        Assert.Equal(new byte[] { 0, 0, 0x01, 0x02, 0x03, 0x04 }, buffer);
    }

    [Fact]
    public void WriteString_WritesLengthPrefixedUtf8()
    {
        var writer = new ByteWriter(20);
        writer.WriteString("hello");
        // First 4 bytes: length (5), then "hello"
        Assert.Equal(9, writer.Position);
        var reader = new ByteReader(writer.Bytes);
        Assert.Equal("hello", reader.ReadString());
    }

    [Fact]
    public void WriteString_Null_WritesZeroLength()
    {
        var writer = new ByteWriter(4);
        writer.WriteString(null);
        Assert.Equal(4, writer.Position);
        Assert.Equal(0u, ByteReader.ReadUInt32(writer.Bytes, 0));
    }

    [Fact]
    public void WriteAsciiString_WritesLengthPrefixedAscii()
    {
        var writer = new ByteWriter(20);
        writer.WriteAsciiString("test");
        var reader = new ByteReader(writer.Bytes);
        Assert.Equal("test", reader.ReadAsciiString());
    }

    [Fact]
    public void WriteBinaryString_WritesLengthPrefixedBytes()
    {
        byte[] data = [0xDE, 0xAD];
        var writer = new ByteWriter(10);
        writer.WriteBinaryString(data);
        var reader = new ByteReader(writer.Bytes);
        Assert.Equal(data, reader.ReadBinaryString());
    }

    [Fact]
    public void WriteNameList_WritesCommaSeparated()
    {
        var nameList = new NameList("aes256-ctr", "aes128-ctr");
        var writer = new ByteWriter(30);
        writer.WriteNameList(nameList);
        var reader = new ByteReader(writer.Bytes);
        var result = reader.ReadNameList();
        Assert.Equal(["aes256-ctr", "aes128-ctr"], result.Names);
    }

    [Fact]
    public void WriteNameList_Empty_WritesZeroLength()
    {
        var nameList = new NameList();
        var writer = new ByteWriter(4);
        writer.WriteNameList(nameList);
        Assert.Equal(4, writer.Position);
        Assert.Equal(0u, ByteReader.ReadUInt32(writer.Bytes, 0));
    }

    [Fact]
    public void WriteByteBlob_Memory_CopiesData()
    {
        byte[] data = [1, 2, 3];
        var writer = new ByteWriter(10);
        writer.WriteByteBlob(data.AsMemory());
        Assert.Equal(3, writer.Position);
        Assert.Equal(data, writer.Bytes[..3]);
    }

    [Fact]
    public void RoundTrip_UInt32()
    {
        uint[] values = [0, 1, 255, 256, 65535, uint.MaxValue];
        foreach (var value in values)
        {
            var writer = new ByteWriter(4);
            writer.WriteUint(value);
            var reader = new ByteReader(writer.Bytes);
            Assert.Equal(value, reader.ReadUInt32());
        }
    }

    [Fact]
    public void RoundTrip_BigInteger()
    {
        var bigInt = new BigInt(new BigInteger(123456789));
        var writer = new ByteWriter(20);
        writer.WriteBigInteger(bigInt);
        var reader = new ByteReader(writer.Bytes);
        var result = reader.ReadBigInteger();
        Assert.Equal(bigInt.BigInteger, result.BigInteger);
    }
}

public class ByteSizerTests
{
    [Fact]
    public void GetByteSize_Returns1() => Assert.Equal(1, ByteSizer.GetByteSize());

    [Fact]
    public void GetBooleanSize_Returns1() => Assert.Equal(1, ByteSizer.GetBooleanSize());

    [Fact]
    public void GetIntSize_Returns4() => Assert.Equal(4, ByteSizer.GetIntSize());

    [Fact]
    public void GetAsciiStringSize_Null_Returns4() => Assert.Equal(4, ByteSizer.GetAsciiStringSize(null));

    [Fact]
    public void GetAsciiStringSize_ReturnsLengthPlus4() => Assert.Equal(9, ByteSizer.GetAsciiStringSize("hello"));

    [Fact]
    public void GetStringSize_Null_Returns4() => Assert.Equal(4, ByteSizer.GetStringSize(null));

    [Fact]
    public void GetStringSize_ReturnsUtf8LengthPlus4() => Assert.Equal(9, ByteSizer.GetStringSize("hello"));

    [Fact]
    public void GetBinaryStringSize_ReturnsLengthPlus4()
    {
        byte[] data = [1, 2, 3];
        Assert.Equal(7, data.GetBinaryStringSize());
    }

    [Fact]
    public void GetByteBlobSize_ReturnsLength()
    {
        byte[] data = [1, 2, 3];
        Assert.Equal(3, data.AsMemory().GetByteBlobSize());
    }

    [Fact]
    public void GetNameListSize_Empty_Returns4()
    {
        var nameList = new NameList();
        Assert.Equal(4, nameList.GetNameListSize());
    }

    [Fact]
    public void GetNameListSize_ReturnsCorrectSize()
    {
        var nameList = new NameList("aes256-ctr", "aes128-ctr");
        // "aes256-ctr,aes128-ctr" = 21 chars + 4 length prefix
        Assert.Equal(25, nameList.GetNameListSize());
    }

    [Fact]
    public void GetBigIntegerSize_ReturnsLengthPlus4()
    {
        var bigInt = new BigInt(new BigInteger(256));
        Assert.Equal(4 + bigInt.Length, bigInt.GetBigIntegerSize());
    }
}
