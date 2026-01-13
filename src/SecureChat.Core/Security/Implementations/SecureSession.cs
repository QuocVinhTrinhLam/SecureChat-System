using SecureChat.Core.Models;
using SecureChat.Core.Security.Interfaces;
using System.Text.Json;

namespace SecureChat.Core.Security.Implementations;

/// <summary>
/// Manages a secure communication session, orchestrating key exchange,
/// encryption, and message signing operations.
/// 
/// Security Design:
/// - Encapsulates all cryptographic state for a session
/// - Enforces proper protocol ordering (key exchange before encryption)
/// - Provides clean encrypt/decrypt methods for message handling
/// 
/// Usage:
/// 1. Create session with InitializeAsync()
/// 2. Perform key exchange: GetKeyExchangeMessage() → ProcessKeyExchangeMessage()
/// 3. Once IsEstablished, use EncryptMessage() and DecryptMessage()
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
    /// Gets whether the session has completed key exchange and is ready for encryption.
    /// </summary>
    public bool IsEstablished => _encryptionKey is not null;

    /// <summary>
    /// Gets the session identifier.
    /// </summary>
    public string? SessionId => _sessionId;

    /// <summary>
    /// Creates a new secure session with default implementations.
    /// </summary>
    public SecureSession()
        : this(new EcdhKeyExchange(), new AesGcmEncryption(), new HmacSha256Signer())
    {
    }

    /// <summary>
    /// Creates a new secure session with custom implementations (for testing).
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
    /// Initializes the session by generating a key pair.
    /// </summary>
    public async Task InitializeAsync()
    {
        ThrowIfDisposed();
        
        _sessionId = Guid.NewGuid().ToString();
        await _keyExchange.GenerateKeyPairAsync();
    }

    /// <summary>
    /// Creates a key exchange message to send to the peer.
    /// </summary>
    /// <param name="senderId">Local user ID.</param>
    /// <param name="senderName">Local username.</param>
    /// <returns>Message containing the public key.</returns>
    public Message GetKeyExchangeMessage(string senderId, string senderName)
    {
        ThrowIfDisposed();
        
        var publicKey = _keyExchange.GetPublicKey();
        
        return new Message
        {
            Type = MessageType.KeyExchange,
            SenderId = senderId,
            SenderName = senderName,
            Content = publicKey,
            SecurityMetadata = new SecurityMetadata
            {
                Algorithm = _keyExchange.AlgorithmIdentifier,
                KeyId = _sessionId
            }
        };
    }

    /// <summary>
    /// Processes a received key exchange message and establishes the session.
    /// </summary>
    /// <param name="message">Key exchange message from peer.</param>
    public async Task ProcessKeyExchangeMessageAsync(Message message)
    {
        ThrowIfDisposed();
        
        if (message.Type != MessageType.KeyExchange)
        {
            throw new ArgumentException("Expected KeyExchange message type", nameof(message));
        }

        if (string.IsNullOrEmpty(message.Content))
        {
            throw new ArgumentException("Key exchange message missing public key", nameof(message));
        }

        if (!_keyExchange.ValidatePublicKey(message.Content))
        {
            throw new SecurityException("Invalid peer public key");
        }

        // Derive shared secret
        var sharedSecret = await _keyExchange.DeriveSharedSecretAsync(message.Content);

        // Derive session keys using HKDF
        // Note: Both parties will derive the same shared secret, and using
        // DeriveSessionKeys (without session-specific salt) ensures both
        // parties derive the same encryption and MAC keys.
        var (encKey, macKey) = HkdfKeyDerivation.DeriveSessionKeys(sharedSecret);

        _encryptionKey = encKey;
        _macKey = macKey;
    }

    /// <summary>
    /// Encrypts a message for transmission.
    /// </summary>
    /// <param name="message">Plaintext message to encrypt.</param>
    /// <returns>Encrypted message ready for transmission.</returns>
    public async Task<Message> EncryptMessageAsync(Message message)
    {
        ThrowIfDisposed();
        ThrowIfNotEstablished();

        // Serialize the original message content
        var plaintextJson = JsonSerializer.Serialize(new
        {
            type = (int)message.Type,
            senderId = message.SenderId,
            senderName = message.SenderName,
            content = message.Content,
            timestamp = message.Timestamp
        });

        // Encrypt the content
        var (ciphertext, iv, tag) = await _encryption.EncryptAsync(plaintextJson, _encryptionKey!);

        // Create encrypted message
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
                KeyId = _sessionId
            }
        };
    }

    /// <summary>
    /// Decrypts a received encrypted message.
    /// </summary>
    /// <param name="encryptedMessage">Encrypted message to decrypt.</param>
    /// <returns>Decrypted plaintext message.</returns>
    public async Task<Message> DecryptMessageAsync(Message encryptedMessage)
    {
        ThrowIfDisposed();
        ThrowIfNotEstablished();

        if (encryptedMessage.Type != MessageType.Encrypted)
        {
            throw new ArgumentException("Expected Encrypted message type", nameof(encryptedMessage));
        }

        var metadata = encryptedMessage.SecurityMetadata 
            ?? throw new ArgumentException("Missing security metadata", nameof(encryptedMessage));

        if (string.IsNullOrEmpty(metadata.InitializationVector) ||
            string.IsNullOrEmpty(metadata.Signature))
        {
            throw new ArgumentException("Incomplete security metadata", nameof(encryptedMessage));
        }

        // Decrypt the content
        var plaintextJson = await _encryption.DecryptAsync(
            encryptedMessage.Content,
            _encryptionKey!,
            metadata.InitializationVector,
            metadata.Signature);

        // Deserialize the inner message
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

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(SecureSession));
        }
    }

    private void ThrowIfNotEstablished()
    {
        if (!IsEstablished)
        {
            throw new InvalidOperationException(
                "Session not established. Complete key exchange first.");
        }
    }

    /// <summary>
    /// Disposes cryptographic resources securely.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        // Dispose key exchange if it's disposable
        if (_keyExchange is IDisposable disposableKeyExchange)
        {
            disposableKeyExchange.Dispose();
        }

        // Clear sensitive key material
        _encryptionKey = null;
        _macKey = null;

        _disposed = true;
    }
}

/// <summary>
/// Security exception for cryptographic failures.
/// </summary>
public class SecurityException : Exception
{
    /// <summary>
    /// Creates a new security exception with the specified message.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SecurityException(string message) : base(message) { }
    
    /// <summary>
    /// Creates a new security exception with the specified message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="inner">The inner exception.</param>
    public SecurityException(string message, Exception inner) : base(message, inner) { }
}
