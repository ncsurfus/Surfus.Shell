﻿using System;

namespace Surfus.Shell.Signing
{
    public abstract class Signer
    {
        public static string[] Supported =>
            new[]
            {
                "rsa-sha2-512",
                "rsa-sha2-256",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
                "ssh-rsa",
                "ssh-dss"
            };
        public abstract string Name { get; }
        public abstract bool VerifySignature(byte[] data, byte[] signature);
        public abstract int KeySize { get; }

        public static Signer CreateSigner(string name, byte[] serverHostKey)
        {
            switch (name)
            {
                case "ecdsa-sha2-nistp256":
                    return new ECDsaSha2Nistp256(serverHostKey);
                case "ecdsa-sha2-nistp384":
                    return new ECDsaSha2Nistp384(serverHostKey);
                case "ecdsa-sha2-nistp521":
                    return new ECDsaSha2Nistp521(serverHostKey);
                case "ssh-rsa":
                    return new SshRsa(serverHostKey);
                case "rsa-sha2-256":
                    return new RsaSha256(serverHostKey);
                case "rsa-sha2-512":
                    return new RsaSha512(serverHostKey);
                case "ssh-dss":
                    return new SshDss(serverHostKey);
                default:
                    throw new Exception("Signing Type Not Supported");
            }
        }
    }
}
