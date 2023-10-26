using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Surfus.Shell.Messages;

namespace Surfus.Shell.Authentication
{
    public interface IAuthenticationHandler
    {
        Task<bool> HandleAsync(ChannelReader<MessageEvent> channelReader, CancellationToken cancellationToken);
    }
}
