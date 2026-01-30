using SecureChat.Core.Models;

namespace SecureChat.Core.Networking;

public interface IMessageSerializer
{
    byte[] Serialize(Message message);
    
    Message Deserialize(byte[] data);
    
    string ContentType { get; }
}
