using SecureChat.Core.Models;
using SecureChat.Core.Security.Interfaces;
using System.Text.Json;

namespace SecureChat.Core.Security.Implementations;
/// <summary>
/// Manages a secure communication session, orchestrating key exchange,
/// encryption, and message authentication
/// </summary>
public sealed class SecureSession : IDisposable
{
    private readonly IKeyExchange _keyExchange;
    private readonly ISymmetricEncryption _encryption;
    private readonly IMessageSigner _signer;
    private string? _sessionId;
    private string? _encryptionKey;
    private string? _macKey;
    private bool _disposed;
    /// <summary>
    /// Gets whether the session has completed key exchange and is ready for encryption
    /// </summary>
    public bool IsEstablished => _encryptionKey is not null;
    /// <summary>
    /// Gets the unique session identifier
    /// </summary>
    public string? SessionId => _sessionId;
    /// <summary>
    /// Creates a secure session with default cryptographic implementations
    /// </summary>
    public SecureSession()
        : this(new EcdhKeyExchange(), new AesGcmEncryption(), new HmacSha256Signer())
    {
    }
    /// <summary>
    /// Creates a secure session with custom cryptographic implementations
    /// </summary>
    public SecureSession(
        IKeyExchange keyExchange,
        ISymmetricEncryption encryption,
        IMessageSigner signer)
    {
        _keyExchange = keyExchange;
        _encryption = encryption;
        _signer = signer;
    }
    /// <summary>
    /// Initializes the session by generating a local key pair
    /// </summary>
    public async Task InitializeAsync()
    {
        ThrowIfDisposed();
        _sessionId = Guid.NewGuid().ToString();
        await _keyExchange.GenerateKeyPairAsync();
    }
    /// <summary>
    /// Creates a key exchange message containing the local public key
    /// </summary>
    public Message GetKeyExchangeMessage(string senderId, string senderName)
    {
        ThrowIfDisposed();
        return new Message
        {
            Type = MessageType.KeyExchange,
            SenderId = senderId,
            SenderName = senderName,
            Content = _keyExchange.GetPublicKey(),
            SecurityMetadata = new SecurityMetadata
            {
                Algorithm = _keyExchange.AlgorithmIdentifier,
                KeyId = _sessionId
            }
        };
    }
    /// <summary>
    /// Processes a received key exchange message and derives session keys
    /// </summary>
    public async Task ProcessKeyExchangeMessageAsync(Message message)
    {
        ThrowIfDisposed();
        if (message.Type != MessageType.KeyExchange)
            throw new ArgumentException("Expected KeyExchange message type", nameof(message));
        if (string.IsNullOrEmpty(message.Content))
            throw new ArgumentException("Key exchange message missing public key", nameof(message));
        if (!_keyExchange.ValidatePublicKey(message.Content))
            throw new SecurityException("Invalid peer public key");
        var sharedSecret = await _keyExchange.DeriveSharedSecretAsync(message.Content);
        var (encKey, macKey) = HkdfKeyDerivation.DeriveSessionKeys(sharedSecret);
        _encryptionKey = encKey;
        _macKey = macKey;
    }
    /// <summary>
    /// Encrypts a plaintext message for secure transmission
    /// Client encrypt outgoing message
    /// </summary>
    public async Task<Message> EncryptMessageAsync(Message message)
    {
        ThrowIfDisposed();
        ThrowIfNotEstablished();
        var plaintextJson = JsonSerializer.Serialize(new
        {
            type = (int)message.Type,
            senderId = message.SenderId,
            senderName = message.SenderName,
            content = message.Content,
            timestamp = message.Timestamp
        });
        var (ciphertext, iv, tag) =
            await _encryption.EncryptAsync(plaintextJson, _encryptionKey!);
        
        // Compute HMAC over ciphertext for integrity verification (Encrypt-then-MAC)
        var hmac = await _signer.SignAsync(ciphertext, _macKey!);
        
        return new Message
        {
            Id = message.Id,
            Type = MessageType.Encrypted,
            SenderId = message.SenderId,
            SenderName = message.SenderName,
            Content = ciphertext,
            Timestamp = message.Timestamp,
            SecurityMetadata = new SecurityMetadata
            {
                Algorithm = _encryption.AlgorithmIdentifier,
                InitializationVector = iv,
                Signature = tag,
                Hmac = hmac,
                KeyId = _sessionId
            }
        };
    }
    /// <summary>
    /// Decrypts a received encrypted message
    /// </summary>
    public async Task<Message> DecryptMessageAsync(Message encryptedMessage)
    {
        ThrowIfDisposed();
        ThrowIfNotEstablished();
        if (encryptedMessage.Type != MessageType.Encrypted)
            throw new ArgumentException("Expected Encrypted message type", nameof(encryptedMessage));
        var metadata = encryptedMessage.SecurityMetadata
            ?? throw new ArgumentException("Missing security metadata", nameof(encryptedMessage));
        if (string.IsNullOrEmpty(metadata.InitializationVector) ||
            string.IsNullOrEmpty(metadata.Signature))
            throw new ArgumentException("Incomplete security metadata", nameof(encryptedMessage));
        if (metadata.Algorithm != _encryption.AlgorithmIdentifier)
            throw new SecurityException($"Unsupported encryption algorithm: {metadata.Algorithm}");
        
        // Verify HMAC before decryption (prevents decryption oracle attacks)
        if (string.IsNullOrEmpty(metadata.Hmac))
            throw new SecurityException("Missing HMAC in encrypted message");
        
        var isHmacValid = await _signer.VerifyAsync(
            encryptedMessage.Content, metadata.Hmac, _macKey!);
        if (!isHmacValid)
            throw new SecurityException("HMAC verification failed - message integrity compromised");
        
        var plaintextJson = await _encryption.DecryptAsync(
            encryptedMessage.Content,
            _encryptionKey!,
            metadata.InitializationVector,
            metadata.Signature);
        var inner = JsonSerializer.Deserialize<JsonElement>(plaintextJson);
        return new Message
        {
            Id = encryptedMessage.Id,
            Type = (MessageType)inner.GetProperty("type").GetInt32(),
            SenderId = inner.GetProperty("senderId").GetString() ?? string.Empty,
            SenderName = inner.GetProperty("senderName").GetString() ?? string.Empty,
            Content = inner.GetProperty("content").GetString() ?? string.Empty,
            Timestamp = inner.GetProperty("timestamp").GetDateTime()
        };
    }
    /// <summary>
    /// Releases cryptographic resources and clears sensitive material
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        if (_keyExchange is IDisposable disposableKeyExchange)
            disposableKeyExchange.Dispose();
        _encryptionKey = null;
        _macKey = null;
        _disposed = true;
    }
    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(SecureSession));
    }
    private void ThrowIfNotEstablished()
    {
        if (!IsEstablished)
            throw new InvalidOperationException(
                "Session not established. Complete key exchange first.");
    }
}
/// <summary>
/// Represents a security-related cryptographic failure
/// </summary>
public class SecurityException : Exception
{
    /// <summary>
    /// Creates a new security exception
    /// </summary>
    public SecurityException(string message) : base(message) { }
    /// <summary>
    /// Creates a new security exception with an inner exception
    /// </summary>
    public SecurityException(string message, Exception inner) : base(message, inner) { }
}