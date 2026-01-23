using SecureChat.Core.Models;

namespace SecureChat.Core.Networking;

/// <summary>
/// Abstraction cho việc serialize/deserialize tin nhắn
/// 
/// Thiết kế bảo mật:
/// - Tách riêng logic serialization khỏi transport để dễ audit
/// - Cho phép các format có thể thay thế được
/// - Implementation cần xác thực cấu trúc tin nhắn trong quá trình deserialization
/// 
/// Lưu ý bảo mật:
/// - Giới hạn kích thước tin nhắn tối đa để ngăn chặn DoS
/// - Xác thực tất cả các field bắt buộc có mặt
/// - Làm sạch các field string để ngăn chặn injection
/// </summary>
public interface IMessageSerializer
{
    /// <summary>
    /// Serialize tin nhắn thành mảng byte để truyền qua mạng
    /// </summary>
    /// <param name="message">Tin nhắn cần serialize.</param>
    /// <returns>Biểu diễn mảng byte của tin nhắn.</returns>
    /// <exception cref="ArgumentNullException">Nếu message là null.</exception>
    byte[] Serialize(Message message);
    
    /// <summary>
    /// Deserialize tin nhắn từ mảng byte
    /// </summary>
    /// <param name="data">Mảng byte cần deserialize.</param>
    /// <returns>Tin nhắn đã được deserialize.</returns>
    /// <exception cref="ArgumentNullException">Nếu data là null.</exception>
    /// <exception cref="FormatException">Nếu data không thể deserialize.</exception>
    /// <remarks>
    /// Bảo mật: Implementation cần xác thực cấu trúc tin nhắn
    /// và từ chối tin nhắn không đúng định dạng trước khi trả về
    /// </remarks>
    Message Deserialize(byte[] data);
    
    /// <summary>
    /// Lấy định danh content type cho serializer này
    /// Sử dụng để đàm phán giao thức
    /// </summary>
    string ContentType { get; }
}
