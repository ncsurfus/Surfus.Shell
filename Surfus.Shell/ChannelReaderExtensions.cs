using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Messages;

namespace Surfus.Shell
{
    public static class ChannelExtensions
    {
        public static async ValueTask<MessageEvent> ReadAsync(
            this ChannelReader<MessageEvent> channelReader,
            MessageType messageType,
            CancellationToken cancellationToken
        )
        {
            var message = await channelReader.ReadAsync(cancellationToken);
            if (message.Type != messageType)
            {
                throw new Exception($"Expected {messageType} got {message.Type}!");
            }
            return message;
        }

        public static async ValueTask<T> ReadAsync<T>(this ChannelReader<MessageEvent> channelReader, CancellationToken cancellationToken)
        {
            var message = await channelReader.ReadAsync(cancellationToken);
            if (message.Message is not T msg)
            {
                throw new Exception($"Expected {typeof(T)} got {message.Message.GetType()}!");
            }
            return msg;
        }
    }
}
