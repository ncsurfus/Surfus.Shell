using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Surfus.SecureShell.Exceptions;
using Surfus.SecureShell.Extensions;
using Org.BouncyCastle.Crypto;

namespace Surfus.SecureShell.Signing
{
    public sealed class SshDss : Signer
    {
        private readonly IDsa _provider;


        public SshDss(byte[] signature)
		{
            Raw = signature;
            using(var memoryStream = new MemoryStream(signature))
            {
                if (Name != memoryStream.ReadString())
                {
                    throw new Exception($"Expected {Name} signature type");
                }
                P = memoryStream.ReadBigInteger();
                Q = memoryStream.ReadBigInteger();
                G = memoryStream.ReadBigInteger();
                Y = memoryStream.ReadBigInteger();
            }
			var Pbc = new Org.BouncyCastle.Math.BigInteger(P.ToString());
			var Qbc = new Org.BouncyCastle.Math.BigInteger(Q.ToString());
			var Gbc = new Org.BouncyCastle.Math.BigInteger(G.ToString());
			var Ybc = new Org.BouncyCastle.Math.BigInteger(Y.ToString());
			var dsaParamters = new Org.BouncyCastle.Crypto.Parameters.DsaParameters(Pbc, Qbc, Gbc);
			var dsaPublicParamters = new Org.BouncyCastle.Crypto.Parameters.DsaPublicKeyParameters(Ybc, dsaParamters);

			_provider = new Org.BouncyCastle.Crypto.Signers.DsaSigner();
			_provider.Init(false, dsaPublicParamters);

           /* _provider = new DSACryptoServiceProvider();
            _provider.ImportParameters(new DSAParameters
            {
                P = P.ToByteArray(), 
                Q = Q.ToByteArray(), 
                G = G.ToByteArray(), 
                Y = Y.ToByteArray()
            });*/
        }

        public BigInteger P { get; }
        public BigInteger Q { get; }
        public BigInteger G { get; }
        public BigInteger Y { get; }

        public override string Name { get; } = "ssh-dss";
        public override byte[] Raw { get; }

        public override bool VerifySignature(byte[] data, byte[] signature)
        {
			Console.WriteLine("Validating ssh-dss");
			using (var memoryStream = new MemoryStream(signature))
			{
				var header = memoryStream.ReadString();
				var blobSize = memoryStream.ReadBinaryString();
				if (header != "ssh-dss" || blobSize.Length != 40)
				{
					throw new SshException("Invalid ssh-dss header.");
				}
				var rBytes = blobSize.Take(20).ToArray();
				var sBytes = blobSize.Skip(20).Take(20).ToArray();
				var rOrg = new Org.BouncyCastle.Math.BigInteger(1, rBytes);
				var sOrg = new Org.BouncyCastle.Math.BigInteger(1, sBytes);

				return _provider.VerifySignature(data, rOrg, sOrg);
			}
        }
    }
}
