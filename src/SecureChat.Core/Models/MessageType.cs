namespace SecureChat.Core.Models;

public enum MessageType
{
    Text = 0,
    
    Join = 1,
    
    Leave = 2,
    
    KeyExchange = 3,
    
    Encrypted = 4,
    
    Error = 5,
    
    System = 6,
    
    UserList = 7,
    
    PeerKeyExchange = 8,
    
    PeerKeyExchangeResponse = 9,
    
    File = 10,
    
    FileChunk = 11,
    
    FileComplete = 12
}
