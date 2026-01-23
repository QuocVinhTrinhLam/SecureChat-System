using SecureChat.Core.Models;
using SecureChat.Core.Security.Interfaces;
using System.Text.Json;

namespace SecureChat.Core.Security.Implementations;
/// <summary>
/// Quản lý phiên giao tiếp bảo mật, điều phối trao đổi khóa,
/// mã hóa và xác thực tin nhắn
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
    /// Kiểm tra phiên đã hoàn thành trao đổi khóa và sẵn sàng mã hóa chưa
    /// </summary>
    public bool IsEstablished => _encryptionKey is not null;
    /// <summary>
    /// Lấy định danh phiên duy nhất
    /// </summary>
    public string? SessionId => _sessionId;
    /// <summary>
    /// Tạo phiên bảo mật với các implementation mật mã mặc định
    /// </summary>
    public SecureSession()
        : this(new EcdhKeyExchange(), new AesGcmEncryption(), new HmacSha256Signer())
    {
    }
    /// <summary>
    /// Tạo phiên bảo mật với các implementation mật mã tùy chỉnh
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
    /// Khởi tạo phiên bằng cách tạo cặp khóa cục bộ
    /// </summary>
    public async Task InitializeAsync()
    {
        ThrowIfDisposed();
        _sessionId = Guid.NewGuid().ToString();
        await _keyExchange.GenerateKeyPairAsync();
    }
    /// <summary>
    /// Tạo tin nhắn trao đổi khóa chứa khóa công khai cục bộ
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
    /// Xử lý tin nhắn trao đổi khóa nhận được và tính session keys
    /// </summary>
    public async Task ProcessKeyExchangeMessageAsync(Message message)
    {
        ThrowIfDisposed();
        if (message.Type != MessageType.KeyExchange)
            throw new ArgumentException("Mong đợi loại tin nhắn KeyExchange", nameof(message));
        if (string.IsNullOrEmpty(message.Content))
            throw new ArgumentException("Tin nhắn trao đổi khóa thiếu public key", nameof(message));
        if (!_keyExchange.ValidatePublicKey(message.Content))
            throw new SecurityException("Khóa công khai của peer không hợp lệ");
        var sharedSecret = await _keyExchange.DeriveSharedSecretAsync(message.Content);
        var (encKey, macKey) = HkdfKeyDerivation.DeriveSessionKeys(sharedSecret);
        _encryptionKey = encKey;
        _macKey = macKey;
    }
    /// <summary>
    /// Mã hóa tin nhắn plaintext để truyền bảo mật
    /// Client mã hóa tin nhắn gửi đi
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
        
        // Tính HMAC trên ciphertext để xác minh tính toàn vẹn
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
    /// Giải mã tin nhắn mã hóa nhận được
    /// </summary>
    public async Task<Message> DecryptMessageAsync(Message encryptedMessage)
    {
        ThrowIfDisposed();
        ThrowIfNotEstablished();
        if (encryptedMessage.Type != MessageType.Encrypted)
            throw new ArgumentException("Mong đợi loại tin nhắn Encrypted", nameof(encryptedMessage));
        var metadata = encryptedMessage.SecurityMetadata
            ?? throw new ArgumentException("Thiếu security metadata", nameof(encryptedMessage));
        if (string.IsNullOrEmpty(metadata.InitializationVector) ||
            string.IsNullOrEmpty(metadata.Signature))
            throw new ArgumentException("Security metadata không đầy đủ", nameof(encryptedMessage));
        if (metadata.Algorithm != _encryption.AlgorithmIdentifier)
            throw new SecurityException($"Thuật toán mã hóa không được hỗ trợ: {metadata.Algorithm}");
        
        // Xác minh HMAC trước khi giải mã
        if (string.IsNullOrEmpty(metadata.Hmac))
            throw new SecurityException("Thiếu HMAC trong tin nhắn mã hóa");
        
        var isHmacValid = await _signer.VerifyAsync(
            encryptedMessage.Content, metadata.Hmac, _macKey!);
        if (!isHmacValid)
            throw new SecurityException("Xác minh HMAC thất bại - tính toàn vẹn tin nhắn bị xâm phạm");
        
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
    /// Giải phóng tài nguyên mật mã và xóa dữ liệu nhạy cảm
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
                "Phiên chưa được thiết lập. Hoàn thành trao đổi khóa trước.");
    }
}
/// <summary>
/// Đại diện cho lỗi mật mã liên quan đến bảo mật
/// </summary>
public class SecurityException : Exception
{
    /// <summary>
    /// Tạo security exception mới
    /// </summary>
    public SecurityException(string message) : base(message) { }
    /// <summary>
    /// Tạo security exception mới với inner exception
    /// </summary>
    public SecurityException(string message, Exception inner) : base(message, inner) { }
}