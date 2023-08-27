using System.Text;

namespace Surfus.Shell.Extensions
{
    public class NameList
    {
        // Reference: https://tools.ietf.org/html/rfc4251#page-10
        public NameList(params string[] names)
        {
            if (names == null || names.Length == 0)
            {
                AsBytes = new byte[] { };
                Names = new string[] { };
                AsString = string.Empty;
                IsEmpty = true;
                return;
            }

            Names = names;
            AsString = string.Join(",", Names);
            AsBytes = Encoding.ASCII.GetBytes(AsString);
        }

        public string[] Names { get; }
        public byte[] AsBytes { get; }
        public string AsString { get; }
        public bool IsEmpty { get; }

        public override string ToString()
        {
            return AsString;
        }
    }
}
