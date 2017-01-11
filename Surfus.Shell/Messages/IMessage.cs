namespace Surfus.Shell.Messages
{
    public interface IMessage
    {
        MessageType Type { get; }
        byte MessageId { get; }
        byte[] GetBytes();
    }
}
