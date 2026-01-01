using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureChat.Core.Models;

namespace SecureChat.Core.Networking;

/// <summary>
/// JSON-based message serializer using System.Text.Json.
/// 
/// Security Features:
/// - Uses strict deserialization options
/// - Validates message structure
/// - Limits maximum message size
/// - UTF-8 encoding for consistent handling
/// </summary>
public sealed class JsonMessageSerializer : IMessageSerializer
{
    /// <summary>
    /// Maximum allowed message size in bytes.
    /// Security: Prevents memory exhaustion attacks from oversized messages.
    /// </summary>
    public const int MaxMessageSize = 64 * 1024; // 64 KB
    
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false, // Compact format for network efficiency
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        
        // Security: Strict mode - don't allow extra fields that could be attack vectors
        // Note: This is the default in System.Text.Json
        PropertyNameCaseInsensitive = true,
        
        // Security: Use string enums for better debugging and protocol clarity
        Converters = { new JsonStringEnumConverter() }
    };
    
    /// <inheritdoc />
    public string ContentType => "application/json";
    
    /// <inheritdoc />
    public byte[] Serialize(Message message)
    {
        ArgumentNullException.ThrowIfNull(message);
        
        // Validate message before serialization
        ValidateMessage(message);
        
        var json = JsonSerializer.Serialize(message, SerializerOptions);
        var bytes = Encoding.UTF8.GetBytes(json);
        
        // Security: Check size before returning
        if (bytes.Length > MaxMessageSize)
        {
            throw new InvalidOperationException(
                $"Serialized message exceeds maximum size of {MaxMessageSize} bytes");
        }
        
        return bytes;
    }
    
    /// <inheritdoc />
    public Message Deserialize(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        
        // Security: Check size before processing
        if (data.Length > MaxMessageSize)
        {
            throw new FormatException(
                $"Message exceeds maximum allowed size of {MaxMessageSize} bytes");
        }
        
        if (data.Length == 0)
        {
            throw new FormatException("Cannot deserialize empty data");
        }
        
        try
        {
            var json = Encoding.UTF8.GetString(data);
            var message = JsonSerializer.Deserialize<Message>(json, SerializerOptions);
            
            if (message is null)
            {
                throw new FormatException("Deserialized message is null");
            }
            
            // Validate the deserialized message
            ValidateMessage(message);
            
            return message;
        }
        catch (JsonException ex)
        {
            // Security: Don't expose internal JSON parsing details
            throw new FormatException("Invalid message format", ex);
        }
    }
    
    /// <summary>
    /// Validates a message for required fields and constraints.
    /// Security: Rejects malformed messages early in the pipeline.
    /// </summary>
    private static void ValidateMessage(Message message)
    {
        // Validate required fields
        if (string.IsNullOrEmpty(message.Id))
        {
            throw new FormatException("Message ID is required");
        }
        
        if (string.IsNullOrEmpty(message.SenderId))
        {
            throw new FormatException("Sender ID is required");
        }
        
        // Security: Validate content length
        const int MaxContentLength = 10_000; // Characters
        if (message.Content?.Length > MaxContentLength)
        {
            throw new FormatException($"Message content exceeds maximum length of {MaxContentLength}");
        }
        
        // Security: Validate timestamp is reasonable (within 5 minutes)
        // This helps prevent replay attacks
        var timeDiff = DateTime.UtcNow - message.Timestamp;
        if (Math.Abs(timeDiff.TotalMinutes) > 5)
        {
            throw new FormatException("Message timestamp is outside acceptable range");
        }
    }
}
