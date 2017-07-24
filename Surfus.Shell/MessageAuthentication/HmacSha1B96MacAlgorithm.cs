﻿using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Surfus.Shell.Extensions;
using System;

namespace Surfus.Shell.MessageAuthentication
{
    internal sealed class HmacSha1B96MacAlgorithm : MacAlgorithm
    {
        private HMACSHA1 _macProvider;

        public override int KeySize { get; protected set; } = 20;
        public override int OutputSize => 12;

        public override void Initialize(byte[] key)
        {
            if(key.Length != KeySize)
            {
                Array.Resize(ref key, KeySize);
            }

            _macProvider = new HMACSHA1
            {
                Key = key
            };
            _macProvider.Initialize();
        }

        public override byte[] ComputeHash(uint sequenceNumber, SshPacket sshPacket)
        {
            ByteWriter.WriteUint(sshPacket.Buffer, 0, sequenceNumber);
            return _macProvider.ComputeHash(sshPacket.Buffer, 0, sshPacket.Length + 4);
        }

        public override bool VerifyMac(uint sequenceNumber, SshPacket sshPacket)
        {
            var computedMac = ComputeHash(sequenceNumber, sshPacket);
            Console.WriteLine("computed Mac Size: " + computedMac.Length);
            for (int i = 0; i != OutputSize; i++)
            {
                if (sshPacket.Buffer[sshPacket.Buffer.Length - OutputSize + i] != computedMac[i])
                {
                    Console.WriteLine(sshPacket.Buffer[sshPacket.Buffer.Length - OutputSize + i] + " - " + computedMac[i]);
                }
            }
            foreach(var x in sshPacket.Buffer)
            {
                Console.Write(x + " ");
            }
            //return false;
            return true;
        }
    }
}
