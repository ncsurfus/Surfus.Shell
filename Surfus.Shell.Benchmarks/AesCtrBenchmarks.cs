using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Surfus.Shell.Crypto;

namespace Surfus.Shell.Benchmarks;

[MemoryDiagnoser]
public class AesCtrBenchmarks
{
    private AesCtrCryptoAlgorithm _crypto;
    private byte[] _1KB;
    private byte[] _32KB;
    private byte[] _64KB;
    private byte[] _16Bytes;

    [GlobalSetup]
    public void Setup()
    {
        _crypto = new AesCtrCryptoAlgorithm(256);
        var key = new byte[32];
        var iv = new byte[16];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(iv);
        _crypto.Initialize(iv, key);

        _1KB = new byte[1024];
        _32KB = new byte[32 * 1024];
        _64KB = new byte[64 * 1024];
        _16Bytes = new byte[16];
        RandomNumberGenerator.Fill(_1KB);
        RandomNumberGenerator.Fill(_32KB);
        RandomNumberGenerator.Fill(_64KB);
        RandomNumberGenerator.Fill(_16Bytes);
    }

    [GlobalCleanup]
    public void Cleanup() => _crypto.Dispose();

    [Benchmark]
    public void Encrypt_1KB()
    {
        var data = (byte[])_1KB.Clone();
        _crypto.Encrypt(data, 0, data.Length);
    }

    [Benchmark]
    public void Encrypt_32KB()
    {
        var data = (byte[])_32KB.Clone();
        _crypto.Encrypt(data, 0, data.Length);
    }

    [Benchmark]
    public void Encrypt_64KB()
    {
        var data = (byte[])_64KB.Clone();
        _crypto.Encrypt(data, 0, data.Length);
    }

    [Benchmark]
    public void TransformBlock_SingleBlock()
    {
        var data = (byte[])_16Bytes.Clone();
        _crypto.Encrypt(data, 0, 16);
    }

    [Benchmark]
    public void TransformBlock_MultipleBlocks()
    {
        var data = new byte[16];
        for (int i = 0; i < 100; i++)
        {
            Buffer.BlockCopy(_16Bytes, 0, data, 0, 16);
            _crypto.Encrypt(data, 0, 16);
        }
    }
}
