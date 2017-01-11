using System;

namespace Surfus.Shell.Exceptions
{
    /// <summary>
    /// The channel request failed exception.
    /// </summary>
    public class ChannelRequestFailedException : ChannelException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ChannelRequestFailedException"/> class.
        /// </summary>
        /// <param name="message">
        /// The message.
        /// </param>
        public ChannelRequestFailedException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ChannelRequestFailedException"/> class.
        /// </summary>
        /// <param name="message">
        /// The message.
        /// </param>
        /// <param name="innerException">
        /// The inner exception.
        /// </param>
        public ChannelRequestFailedException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

    }
}
