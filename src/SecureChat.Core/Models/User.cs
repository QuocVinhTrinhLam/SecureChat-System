namespace SecureChat.Core.Models;

/// <summary>
/// Đại diện cho một người dùng trong hệ thống chat
/// Lưu ý bảo mật: Class này chứa thông tin định danh và sẽ được mở rộng
/// với key material công khai cho các thao tác mật mã
/// </summary>
public sealed class User
{
    /// <summary>
    /// Định danh người dùng duy nhất
    /// Bảo mật: Chủ yếu sử dụng để theo dõi phía server
    /// ID do client tạo ra cần được xác thực/thay thế bởi server
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    /// <summary>
    /// Tên hiển thị của người dùng
    /// Lưu ý bảo mật: Phải được làm sạch trước khi hiển thị để ngăn chặn injection
    /// Cân nhắc giới hạn độ dài và hạn chế ký tự
    /// </summary>
    public string Username { get; set; } = string.Empty;
    
    /// <summary>
    /// Khóa công khai của người dùng cho các thao tác bất đối xứng
    /// Sử dụng cho: Trao đổi khóa, xác minh chữ ký tin nhắn
    /// Bảo mật: Đây là dữ liệu CÔNG KHAI - an toàn để chia sẻ
    /// Sẽ được điền trong giai đoạn trao đổi khóa
    /// </summary>
    public string? PublicKey { get; set; }
    
    /// <summary>
    /// Timestamp khi người dùng kết nối đến server
    /// Sử dụng để quản lý phiên và ghi log audit
    /// </summary>
    public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Cho biết người dùng đã hoàn thành trao đổi khóa chưa
    /// Bảo mật: Tin nhắn từ người dùng chưa hoàn thành trao đổi khóa
    /// cần bị từ chối trong chế độ bảo mật
    /// </summary>
    public bool IsKeyExchangeComplete { get; set; } = false;
    
    /// <summary>
    /// Tạo người dùng mới với username được chỉ định
    /// </summary>
    /// <param name="username">Tên hiển thị cho người dùng.</param>
    /// <returns>Một instance User mới.</returns>
    public static User Create(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Username không được để trống", nameof(username));
        }
        
        // Bảo mật: Xác thực username cơ bản
        // Trong môi trường production, thêm xác thực đầy đủ hơn
        const int MaxUsernameLength = 32;
        if (username.Length > MaxUsernameLength)
        {
            throw new ArgumentException($"Username không được vượt quá {MaxUsernameLength} ký tự", nameof(username));
        }
        
        return new User
        {
            Username = username.Trim()
        };
    }
}
