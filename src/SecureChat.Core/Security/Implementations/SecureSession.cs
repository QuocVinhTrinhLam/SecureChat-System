using SecureChat.Core.Models;
using SecureChat.Core.Security.Interfaces;
using System.Text.Json;

namespace SecureChat.Core.Security.Implementations;
public sealed class SecureSession : IDisposable
{
    private readonly IKeyExchange _keyExchange;
    private readonly ISymmetricEncryption _encryption;
    private readonly IMessageSigner _signer;
    private string? _sessionId;
    private string? _encryptionKey;
    private string? _macKey;
    private bool _disposed;
    public bool IsEstablished => _encryptionKey is not null;
    public string? SessionId => _sessionId;
    public SecureSession()
        : this(new EcdhKeyExchange(), new AesGcmEncryption(), new HmacSha256Signer())
    {
    }
    public SecureSession(
        IKeyExchange keyExchange,
        ISymmetricEncryption encryption,
        IMessageSigner signer)
    {
        _keyExchange = keyExchange;
        _encryption = encryption;
        _signer = signer;
    }
    public async Task InitializeAsync()
    {
        ThrowIfDisposed();
        _sessionId = Guid.NewGuid().ToString();
        await _keyExchange.GenerateKeyPairAsync();
    }
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
    public async Task ProcessKeyExchangeMessageAsync(Message message)
    {
        ThrowIfDisposed();
        if (message.Type != MessageType.KeyExchange)
            throw new ArgumentException("Expected KeyExchange message", nameof(message));
        if (string.IsNullOrEmpty(message.Content))
            throw new ArgumentException("Key exchange missing public key", nameof(message));
        if (!_keyExchange.ValidatePublicKey(message.Content))
            throw new SecurityException("Invalid peer public key");
        var sharedSecret = await _keyExchange.DeriveSharedSecretAsync(message.Content);
        var (encKey, macKey) = HkdfKeyDerivation.DeriveSessionKeys(sharedSecret);
        _encryptionKey = encKey;
        _macKey = macKey;
    }
    public async Task<Message> EncryptMessageAsync(Message message)
    {
        ThrowIfDisposed();
        ThrowIfNotEstablished();
        var plaintextJson = JsonSerializer.Serialize(new
        {
            type = (int)message.Type,
            senderId = message.SenderId,
            senderName = message.SenderName,
            recipientId = message.RecipientId,
            recipientName = message.RecipientName,
            content = message.Content,
            timestamp = message.Timestamp,
            fileMetadata = message.FileMetadata,
            fileChunkData = message.FileChunkData
        });
        var (ciphertext, iv, tag) =
            await _encryption.EncryptAsync(plaintextJson, _encryptionKey!);
        
        // Calculate HMAC for integrity
        var hmac = await _signer.SignAsync(ciphertext, _macKey!);
        
        return new Message
        {
            Id = message.Id,
            Type = MessageType.Encrypted,
            SenderId = message.SenderId,
            SenderName = message.SenderName,
            RecipientId = message.RecipientId,
            RecipientName = message.RecipientName,
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
    public async Task<Message> DecryptMessageAsync(Message encryptedMessage)
    {
        ThrowIfDisposed();
        ThrowIfNotEstablished();
        if (encryptedMessage.Type != MessageType.Encrypted)
            throw new ArgumentException("Expected Encrypted message", nameof(encryptedMessage));
        var metadata = encryptedMessage.SecurityMetadata
            ?? throw new ArgumentException("Missing security metadata", nameof(encryptedMessage));
        if (string.IsNullOrEmpty(metadata.InitializationVector) ||
            string.IsNullOrEmpty(metadata.Signature))
            throw new ArgumentException("Incomplete security metadata", nameof(encryptedMessage));
        if (metadata.Algorithm != _encryption.AlgorithmIdentifier)
            throw new SecurityException($"Unsupported algorithm: {metadata.Algorithm}");
        
        // Verify HMAC
        if (string.IsNullOrEmpty(metadata.Hmac))
            throw new SecurityException("Missing HMAC");
        
        var isHmacValid = await _signer.VerifyAsync(
            encryptedMessage.Content, metadata.Hmac, _macKey!);
        if (!isHmacValid)
            throw new SecurityException("HMAC verification failed - integrity compromised");
        
        var plaintextJson = await _encryption.DecryptAsync(
            encryptedMessage.Content,
            _encryptionKey!,
            metadata.InitializationVector,
            metadata.Signature);
        var inner = JsonSerializer.Deserialize<JsonElement>(plaintextJson);
        
        // Lấy recipientId và recipientName nếu có
        string? recipientId = null;
        string? recipientName = null;
        if (inner.TryGetProperty("recipientId", out var recipientIdProp) && recipientIdProp.ValueKind != JsonValueKind.Null)
            recipientId = recipientIdProp.GetString();
        if (inner.TryGetProperty("recipientName", out var recipientNameProp) && recipientNameProp.ValueKind != JsonValueKind.Null)
            recipientName = recipientNameProp.GetString();
        
        // Parse FileMetadata if present
        FileMetadata? fileMetadata = null;
        if (inner.TryGetProperty("fileMetadata", out var fileMetadataProp) && fileMetadataProp.ValueKind != JsonValueKind.Null)
        {
            fileMetadata = JsonSerializer.Deserialize<FileMetadata>(fileMetadataProp.GetRawText());
        }
        
        // Parse FileChunkData if present
        FileChunkData? fileChunkData = null;
        if (inner.TryGetProperty("fileChunkData", out var fileChunkDataProp) && fileChunkDataProp.ValueKind != JsonValueKind.Null)
        {
            fileChunkData = JsonSerializer.Deserialize<FileChunkData>(fileChunkDataProp.GetRawText());
        }
        
        return new Message
        {
            Id = encryptedMessage.Id,
            Type = (MessageType)inner.GetProperty("type").GetInt32(),
            SenderId = inner.GetProperty("senderId").GetString() ?? string.Empty,
            SenderName = inner.GetProperty("senderName").GetString() ?? string.Empty,
            RecipientId = recipientId,
            RecipientName = recipientName,
            Content = inner.GetProperty("content").GetString() ?? string.Empty,
            Timestamp = inner.GetProperty("timestamp").GetDateTime(),
            FileMetadata = fileMetadata,
            FileChunkData = fileChunkData
        };
    }
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
public class SecurityException : Exception
{
    public SecurityException(string message) : base(message) { }
    public SecurityException(string message, Exception inner) : base(message, inner) { }
}