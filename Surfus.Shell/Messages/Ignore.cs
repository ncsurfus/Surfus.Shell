namespace Surfus.Shell.Messages
{
    public class Ignore : IClientMessage
    {
        public Ignore(SshPacket packet)
        {
            Data = packet.Reader.ReadString();
        }

        public Ignore(string data)
        {
            Data = data;
        }

        public string Data { get; }

        public MessageType Type { get; } = MessageType.SSH_MSG_IGNORE;
        public byte MessageId => (byte)Type;

        public ByteWriter GetByteWriter()
        {
            var writer = new ByteWriter(Type, Data.GetStringSize());
            writer.WriteString(Data);
            return writer;
        }
    }
}
