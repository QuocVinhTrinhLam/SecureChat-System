using System.Text.Json.Serialization;

namespace SecureChat.Core.Models;

/// <summary>
/// Contains cryptographic metadata required for secure message processing.
/// Security Note: This metadata travels with encrypted messages to enable
/// decryption and integrity verification by the recipient.
/// </summary>
public sealed class SecurityMetadata
{
    /// <summary>
    /// Algorithm identifier (e.g., "AES-256-GCM", "ChaCha20-Poly1305").
    /// Security: Must be validated against allowed algorithms list.
    /// </summary>
    [JsonPropertyName("algorithm")]
    public string? Algorithm { get; set; }
    
    /// <summary>
    /// Initialization Vector for symmetric encryption.
    /// Security Critical: Must be unique per message. Never reuse IVs!
    /// Base64 encoded for JSON transport.
    /// </summary>
    [JsonPropertyName("iv")]
    public string? InitializationVector { get; set; }
    
    /// <summary>
    /// Message authentication code or digital signature.
    /// Security: Verified before decryption to prevent oracle attacks.
    /// Base64 encoded for JSON transport.
    /// </summary>
    [JsonPropertyName("signature")]
    public string? Signature { get; set; }
    
    /// <summary>
    /// Key identifier if using key rotation.
    /// Helps recipient select correct decryption key.
    /// </summary>
    [JsonPropertyName("keyId")]
    public string? KeyId { get; set; }
}

/// <summary>
/// Core message model for all chat system communication.
/// Designed to be extensible for both plaintext and encrypted modes.
/// 
/// Security Design Decisions:
/// - Immutable sender information prevents tampering after creation
/// - Timestamp for replay attack detection (validated by server)
/// - Separate SecurityMetadata for clean encrypted/plaintext handling
/// </summary>
public sealed class Message
{
    /// <summary>
    /// Unique message identifier (UUID v4).
    /// Security: Used for deduplication and replay attack prevention.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    /// <summary>
    /// Type of message being sent.
    /// Security: Server validates type matches expected protocol state.
    /// </summary>
    [JsonPropertyName("type")]
    public MessageType Type { get; set; } = MessageType.Text;
    
    /// <summary>
    /// Unique identifier of the sending user.
    /// Security: Server validates this matches authenticated session.
    /// </summary>
    [JsonPropertyName("senderId")]
    public string SenderId { get; set; } = string.Empty;
    
    /// <summary>
    /// Display name of the sender.
    /// Security Note: This is user-provided and should be sanitized for display.
    /// </summary>
    [JsonPropertyName("senderName")]
    public string SenderName { get; set; } = string.Empty;
    
    /// <summary>
    /// Message content (plaintext or encrypted ciphertext).
    /// When Type is Encrypted, this contains Base64-encoded ciphertext.
    /// Security: Maximum length should be enforced to prevent DoS.
    /// </summary>
    [JsonPropertyName("content")]
    public string Content { get; set; } = string.Empty;
    
    /// <summary>
    /// UTC timestamp when message was created.
    /// Security: Used for replay detection. Server rejects stale messages.
    /// </summary>
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Cryptographic metadata for encrypted messages.
    /// Null for plaintext messages in foundation phase.
    /// </summary>
    [JsonPropertyName("securityMetadata")]
    public SecurityMetadata? SecurityMetadata { get; set; }
    
    /// <summary>
    /// Creates a simple text message.
    /// </summary>
    public static Message CreateTextMessage(string senderId, string senderName, string content)
    {
        return new Message
        {
            Type = MessageType.Text,
            SenderId = senderId,
            SenderName = senderName,
            Content = content
        };
    }
    
    /// <summary>
    /// Creates a system announcement message.
    /// </summary>
    public static Message CreateSystemMessage(string content)
    {
        return new Message
        {
            Type = MessageType.System,
            SenderId = "SYSTEM",
            SenderName = "System",
            Content = content
        };
    }
    
    /// <summary>
    /// Creates a join notification message.
    /// </summary>
    public static Message CreateJoinMessage(string userId, string userName)
    {
        return new Message
        {
            Type = MessageType.Join,
            SenderId = userId,
            SenderName = userName,
            Content = $"{userName} has joined the chat"
        };
    }
    
    /// <summary>
    /// Creates a leave notification message.
    /// </summary>
    public static Message CreateLeaveMessage(string userId, string userName)
    {
        return new Message
        {
            Type = MessageType.Leave,
            SenderId = userId,
            SenderName = userName,
            Content = $"{userName} has left the chat"
        };
    }
}
