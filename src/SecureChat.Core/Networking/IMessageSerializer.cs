using SecureChat.Core.Models;

namespace SecureChat.Core.Networking;

/// <summary>
/// Abstraction for message serialization/deserialization.
/// 
/// Security Design:
/// - Separates serialization logic from transport for easier auditing
/// - Allows pluggable formats (JSON, Protocol Buffers, etc.)
/// - Implementations should validate message structure during deserialization
/// 
/// Security Considerations:
/// - Limit maximum message size to prevent DoS
/// - Validate all required fields are present
/// - Sanitize string fields to prevent injection
/// </summary>
public interface IMessageSerializer
{
    /// <summary>
    /// Serializes a message to byte array for network transmission.
    /// </summary>
    /// <param name="message">The message to serialize.</param>
    /// <returns>Byte array representation of the message.</returns>
    /// <exception cref="ArgumentNullException">If message is null.</exception>
    byte[] Serialize(Message message);
    
    /// <summary>
    /// Deserializes a message from byte array.
    /// </summary>
    /// <param name="data">The byte array to deserialize.</param>
    /// <returns>The deserialized message.</returns>
    /// <exception cref="ArgumentNullException">If data is null.</exception>
    /// <exception cref="FormatException">If data cannot be deserialized.</exception>
    /// <remarks>
    /// Security: Implementation should validate the message structure
    /// and reject malformed messages before returning.
    /// </remarks>
    Message Deserialize(byte[] data);
    
    /// <summary>
    /// Gets the content type identifier for this serializer.
    /// Used for protocol negotiation.
    /// </summary>
    string ContentType { get; }
}
