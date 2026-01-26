namespace SecureChat.Core.Models;

/// <summary>
/// Định nghĩa các loại tin nhắn có thể được trao đổi trong hệ thống chat
/// Lưu ý bảo mật: Loại tin nhắn giúp thực thi máy trạng thái giao thức và ngăn chặn
/// các thao tác không đúng thứ tự
/// </summary>
public enum MessageType
{
    /// <summary>
    /// Tin nhắn văn bản thông thường giữa người dùng
    /// Trong các giai đoạn tiếp theo, nội dung này sẽ được mã hóa với session keys
    /// </summary>
    Text = 0,
    
    /// <summary>
    /// Người dùng tham gia phòng chat
    /// Bảo mật: Kích hoạt giao thức trao đổi khóa trong chế độ bảo mật
    /// </summary>
    Join = 1,
    
    /// <summary>
    /// Người dùng rời khỏi phòng chat
    /// Bảo mật: Nên kích hoạt rotation khóa phiên để đảm bảo forward secrecy
    /// </summary>
    Leave = 2,
    
    /// <summary>
    /// Tin nhắn trao đổi khóa để thiết lập session keys
    /// Chứa key material công khai
    /// Bảo mật quan trọng: Phải xác thực các tham số khóa để ngăn chặn MITM
    /// </summary>
    KeyExchange = 3,
    
    /// <summary>
    /// Tin nhắn payload đã mã hóa
    /// Nội dung là ciphertext; yêu cầu SecurityMetadata để giải mã
    /// </summary>
    Encrypted = 4,
    
    /// <summary>
    /// Thông báo lỗi từ server hoặc client
    /// Bảo mật: Không nên tiết lộ thông tin nhạy cảm trong thông báo lỗi
    /// </summary>
    Error = 5,
    
    /// <summary>
    /// Tin nhắn broadcast từ hệ thống/server
    /// Sử dụng cho thông báo và cập nhật trạng thái kết nối
    /// </summary>
    System = 6,
    
    /// <summary>
    /// Danh sách người dùng online
    /// Server gửi khi có người join/leave để cập nhật danh sách cho clients
    /// </summary>
    UserList = 7,
    
    /// <summary>
    /// Yêu cầu trao đổi khóa trực tiếp giữa hai clients (E2E)
    /// Chứa public key của người gửi, server chỉ chuyển tiếp không đọc được
    /// Bảo mật: Cho phép thiết lập shared secret giữa clients mà server không biết
    /// </summary>
    PeerKeyExchange = 8,
    
    /// <summary>
    /// Phản hồi trao đổi khóa từ peer
    /// Chứa public key của người nhận để hoàn tất ECDH giữa clients
    /// </summary>
    PeerKeyExchangeResponse = 9
}
