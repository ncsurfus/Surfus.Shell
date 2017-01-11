using System;

namespace Surfus.Shell.Signing
{
    public abstract class Signer
    {
        public static string[] Supported => new[] { "ssh-rsa"/*, "ssh-dss"*/ };
        public abstract string Name { get; }
        public abstract byte[] Raw { get; }
        public abstract bool VerifySignature(byte[] data, byte[] signature);

        public static Signer CreateSigner(string name, byte[] serverHostKey)
        {
            switch (name)
            {
                case "ssh-rsa":
                    return new SshRsa(serverHostKey);
                //case "ssh-dss":
                  //  return new SshDss(serverHostKey);
                default:
                    throw new Exception("Signing Type Not Supported");
            }
        }
    }
}
