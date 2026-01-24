using System.Text.Json.Serialization;

namespace SecureChat.Core.Models;

/// <summary>
/// Chứa metadata mật mã cần thiết để xử lý tin nhắn bảo mật
/// Lưu ý bảo mật: Metadata này đi kèm với tin nhắn mã hóa để cho phép
/// giải mã và xác minh tính toàn vẹn bởi người nhận
/// </summary>
public sealed class SecurityMetadata
{
    /// <summary>
    /// Định danh thuật toán
    /// Bảo mật: Phải được xác thực với danh sách thuật toán được phép
    /// </summary>
    [JsonPropertyName("algorithm")]
    public string? Algorithm { get; set; }
    
    /// <summary>
    /// Vector khởi tạo cho mã hóa đối xứng
    /// Bảo mật quan trọng: Phải là duy nhất cho mỗi tin nhắn. Không bao giờ tái sử dụng IV!
    /// Được mã hóa Base64 để truyền JSON
    /// </summary>
    [JsonPropertyName("iv")]
    public string? InitializationVector { get; set; }
    
    /// <summary>
    /// Mã xác thực tin nhắn hoặc chữ ký số
    /// Bảo mật: Được xác minh trước khi giải mã để ngăn chặn oracle attacks
    /// Được mã hóa Base64 để truyền JSON
    /// </summary>
    [JsonPropertyName("signature")]
    public string? Signature { get; set; }
    
    /// <summary>
    /// HMAC để xác minh tính toàn vẹn tin nhắn
    /// Được mã hóa Base64. Xác minh trước khi giải mã để ngăn chặn oracle attacks
    /// </summary>
    [JsonPropertyName("hmac")]
    public string? Hmac { get; set; }
    
    /// <summary>
    /// Định danh khóa nếu sử dụng key rotation
    /// Giúp người nhận chọn đúng khóa giải mã
    /// </summary>
    [JsonPropertyName("keyId")]
    public string? KeyId { get; set; }
}

/// <summary>
/// Model tin nhắn cốt lõi cho tất cả giao tiếp trong hệ thống chat
/// Được thiết kế để mở rộng cho cả chế độ plaintext và encrypted
/// 
/// Quyết định thiết kế bảo mật:
/// - Thông tin người gửi không thể thay đổi ngăn chặn giả mạo sau khi tạo
/// - Timestamp để phát hiện replay attack
/// - SecurityMetadata riêng biệt để xử lý rõ ràng giữa encrypted/plaintext
/// </summary>
public sealed class Message
{
    /// <summary>
    /// Định danh tin nhắn duy nhất
    /// Bảo mật: Sử dụng để loại bỏ trùng lặp và ngăn chặn replay attack
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    /// <summary>
    /// Loại tin nhắn được gửi
    /// Bảo mật: Server xác thực loại khớp với trạng thái giao thức mong đợi
    /// </summary>
    [JsonPropertyName("type")]
    public MessageType Type { get; set; } = MessageType.Text;
    
    /// <summary>
    /// Định danh duy nhất của người gửi
    /// Bảo mật: Server xác thực điều này khớp với phiên đã xác thực
    /// </summary>
    [JsonPropertyName("senderId")]
    public string SenderId { get; set; } = string.Empty;
    
    /// <summary>
    /// Tên hiển thị của người gửi
    /// Lưu ý bảo mật: Đây là dữ liệu do người dùng cung cấp và cần được làm sạch khi hiển thị
    /// </summary>
    [JsonPropertyName("senderName")]
    public string SenderName { get; set; } = string.Empty;
    
    /// <summary>
    /// Nội dung tin nhắn
    /// Khi Type là Encrypted, chứa ciphertext được mã hóa Base64
    /// Bảo mật: Độ dài tối đa cần được áp dụng để ngăn chặn DoS
    /// </summary>
    [JsonPropertyName("content")]
    public string Content { get; set; } = string.Empty;
    
    /// <summary>
    /// Timestamp UTC khi tin nhắn được tạo
    /// Bảo mật: Sử dụng để phát hiện replay. Server từ chối tin nhắn cũ
    /// </summary>
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Metadata mật mã cho tin nhắn mã hóa
    /// Null cho tin nhắn plaintext trong giai đoạn nền tảng
    /// </summary>
    [JsonPropertyName("securityMetadata")]
    public SecurityMetadata? SecurityMetadata { get; set; }
    
    /// <summary>
    /// ID người nhận cho tin nhắn trực tiếp.
    /// Null cho tin nhắn broadcast.
    /// </summary>
    [JsonPropertyName("recipientId")]
    public string? RecipientId { get; set; }
    
    /// <summary>
    /// Tên hiển thị người nhận cho tin nhắn trực tiếp.
    /// </summary>
    [JsonPropertyName("recipientName")]
    public string? RecipientName { get; set; }
    
    /// <summary>
    /// Tạo tin nhắn text đơn giản
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
    /// Tạo tin nhắn trực tiếp đến người nhận cụ thể
    /// </summary>
    public static Message CreateDirectMessage(
        string senderId, string senderName,
        string recipientId, string recipientName,
        string content)
    {
        return new Message
        {
            Type = MessageType.Text,
            SenderId = senderId,
            SenderName = senderName,
            RecipientId = recipientId,
            RecipientName = recipientName,
            Content = content
        };
    }
    
    /// <summary>
    /// Tạo tin nhắn thông báo hệ thống
    /// </summary>
    public static Message CreateSystemMessage(string content)
    {
        return new Message
        {
            Type = MessageType.System,
            SenderId = "SYSTEM",
            SenderName = "Hệ thống",
            Content = content
        };
    }
    
    /// <summary>
    /// Tạo tin nhắn thông báo tham gia
    /// </summary>
    public static Message CreateJoinMessage(string userId, string userName)
    {
        return new Message
        {
            Type = MessageType.Join,
            SenderId = userId,
            SenderName = userName,
            Content = $"{userName} đã tham gia chat"
        };
    }
    
    /// <summary>
    /// Tạo tin nhắn thông báo rời đi
    /// </summary>
    public static Message CreateLeaveMessage(string userId, string userName)
    {
        return new Message
        {
            Type = MessageType.Leave,
            SenderId = userId,
            SenderName = userName,
            Content = $"{userName} đã rời khỏi chat"
        };
    }
    
    /// <summary>
    /// Tạo tin nhắn danh sách người dùng online
    /// Content chứa danh sách usernames phân cách bởi dấu phẩy
    /// </summary>
    public static Message CreateUserListMessage(IEnumerable<string> usernames)
    {
        return new Message
        {
            Type = MessageType.UserList,
            SenderId = "SYSTEM",
            SenderName = "Hệ thống",
            Content = string.Join(",", usernames)
        };
    }
}
