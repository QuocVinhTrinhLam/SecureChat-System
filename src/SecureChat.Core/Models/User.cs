namespace SecureChat.Core.Models;

/// <summary>
/// Represents a user in the chat system
/// Security Note: This class holds identity information and will be extended
/// with public key material for cryptographic operations
/// </summary>
public sealed class User
{
    /// <summary>
    /// Unique user identifier
    /// Security: Used primarily for server-side tracking
    /// Client-generated IDs should be validated/replaced by server
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    /// <summary>
    /// User's display name
    /// Security Note: Must be sanitized before display to prevent injection
    /// Consider length limits and character restrictions
    /// </summary>
    public string Username { get; set; } = string.Empty;
    
    /// <summary>
    /// User's public key for asymmetric operations
    /// Used for: Key exchange, message signing verification
    /// Security: This is PUBLIC data - safe to share
    /// Will be populated during key exchange phase
    /// </summary>
    public string? PublicKey { get; set; }
    
    /// <summary>
    /// Timestamp when user connected to the server
    /// Used for session management and audit logging
    /// </summary>
    public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Indicates if the user has completed key exchange
    /// Security: Messages from users without completed key exchange
    /// should be rejected in secure mode
    /// </summary>
    public bool IsKeyExchangeComplete { get; set; } = false;
    
    /// <summary>
    /// Creates a new user with the specified username
    /// </summary>
    /// <param name="username">Display name for the user.</param>
    /// <returns>A new User instance.</returns>
    public static User Create(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Username cannot be empty", nameof(username));
        }
        
        // Security: Basic username validation
        // In production, add more robust validation
        const int MaxUsernameLength = 32;
        if (username.Length > MaxUsernameLength)
        {
            throw new ArgumentException($"Username cannot exceed {MaxUsernameLength} characters", nameof(username));
        }
        
        return new User
        {
            Username = username.Trim()
        };
    }
}
