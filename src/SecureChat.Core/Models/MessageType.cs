namespace SecureChat.Core.Models;

/// <summary>
/// Defines the types of messages that can be exchanged in the chat system.
/// Security Note: Message types help enforce protocol state machine and prevent
/// out-of-order operations (e.g., sending chat before key exchange).
/// </summary>
public enum MessageType
{
    /// <summary>
    /// Regular text message between users.
    /// In future phases, this content will be encrypted with session keys.
    /// </summary>
    Text = 0,
    
    /// <summary>
    /// User joining the chat room.
    /// Security: Triggers key exchange protocol in secure mode.
    /// </summary>
    Join = 1,
    
    /// <summary>
    /// User leaving the chat room.
    /// Security: Should trigger session key rotation for forward secrecy.
    /// </summary>
    Leave = 2,
    
    /// <summary>
    /// Key exchange message for establishing session keys.
    /// Contains public key material (RSA/ECDH parameters).
    /// Security Critical: Must validate key parameters to prevent MITM.
    /// </summary>
    KeyExchange = 3,
    
    /// <summary>
    /// Encrypted payload message.
    /// Content is ciphertext; requires SecurityMetadata for decryption.
    /// </summary>
    Encrypted = 4,
    
    /// <summary>
    /// Error notification from server or client.
    /// Security: Should not leak sensitive information in error messages.
    /// </summary>
    Error = 5,
    
    /// <summary>
    /// System/server broadcast message.
    /// Used for announcements and connection status updates.
    /// </summary>
    System = 6
}
