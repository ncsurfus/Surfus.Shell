﻿namespace Surfus.Shell.Messages
{
    public interface IClientMessage : IMessage
    {
        /// <summary>
        /// Gets the unencrypted SSH packet bytes.
        /// </summary>
        /// <returns></returns>
        ByteWriter GetByteWriter();
    }
}
