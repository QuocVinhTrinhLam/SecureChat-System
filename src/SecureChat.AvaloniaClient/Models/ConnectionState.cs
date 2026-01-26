namespace SecureChat.AvaloniaClient.Models;

/// <summary>
/// Trạng thái kết nối của client
/// </summary>
public enum ConnectionState
{
    /// <summary>
    /// Chưa kết nối
    /// </summary>
    Disconnected,
    
    /// <summary>
    /// Đang kết nối
    /// </summary>
    Connecting,
    
    /// <summary>
    /// Đã kết nối và sẵn sàng
    /// </summary>
    Connected,
    
    /// <summary>
    /// Đang ngắt kết nối
    /// </summary>
    Disconnecting,
    
    /// <summary>
    /// Lỗi kết nối
    /// </summary>
    Error
}
