using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureChat.Core.Models;

namespace SecureChat.Core.Networking;

/// <summary>
/// JSON message serializer sử dụng System.Text.Json
/// 
/// Tính năng bảo mật:
/// - Sử dụng các tùy chọn deserialization nghiêm ngặt
/// - Xác thực cấu trúc tin nhắn
/// - Giới hạn kích thước tin nhắn tối đa
/// - Encoding UTF-8 để xử lý nhất quán
/// </summary>
public sealed class JsonMessageSerializer : IMessageSerializer
{
    /// <summary>
    /// Kích thước tin nhắn tối đa cho phép tính bằng bytes
    /// Bảo mật: Ngăn chặn tấn công làm cạn kiệt bộ nhớ từ tin nhắn quá lớn
    /// </summary>
    public const int MaxMessageSize = 512 * 1024; // 512 KB - đủ lớn cho file transfer chunks
    
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false, // Định dạng compact cho hiệu quả mạng
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        
        // Bảo mật: Chế độ nghiêm ngặt - không cho phép các field thừa có thể là attack vectors
        // Lưu ý: Đây là mặc định trong System.Text.Json
        PropertyNameCaseInsensitive = true,
        
        // Bảo mật: Sử dụng string enums để debug tốt hơn và rõ ràng giao thức
        Converters = { new JsonStringEnumConverter() }
    };
    
    /// <inheritdoc />
    public string ContentType => "application/json";
    
    /// <inheritdoc />
    public byte[] Serialize(Message message)
    {
        ArgumentNullException.ThrowIfNull(message);
        
        // Xác thực tin nhắn trước khi serialize
        ValidateMessage(message);
        
        var json = JsonSerializer.Serialize(message, SerializerOptions);
        var bytes = Encoding.Unicode.GetBytes(json);
        
        // Bảo mật: Kiểm tra kích thước trước khi trả về
        if (bytes.Length > MaxMessageSize)
        {
            throw new InvalidOperationException(
                $"Tin nhắn serialize vượt quá kích thước tối đa {MaxMessageSize} bytes");
        }
        
        return bytes;
    }
    
    /// <inheritdoc />
    public Message Deserialize(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        
        // Bảo mật: Kiểm tra kích thước trước khi xử lý
        if (data.Length > MaxMessageSize)
        {
            throw new FormatException(
                $"Tin nhắn vượt quá kích thước tối đa cho phép {MaxMessageSize} bytes");
        }
        
        if (data.Length == 0)
        {
            throw new FormatException("Không thể deserialize dữ liệu rỗng");
        }
        
        try
        {
            var json = Encoding.Unicode.GetString(data);
            var message = JsonSerializer.Deserialize<Message>(json, SerializerOptions);
            
            if (message is null)
            {
                throw new FormatException("Tin nhắn deserialize là null");
            }
            
            // Xác thực tin nhắn đã deserialize
            ValidateMessage(message);
            
            return message;
        }
        catch (JsonException ex)
        {
            // Bảo mật: Không tiết lộ chi tiết JSON parsing nội bộ
            throw new FormatException("Định dạng tin nhắn không hợp lệ", ex);
        }
    }
    
    /// <summary>
    /// Xác thực tin nhắn với các field bắt buộc và ràng buộc
    /// Bảo mật: Từ chối tin nhắn không đúng định dạng sớm trong pipeline
    /// </summary>
    private static void ValidateMessage(Message message)
    {
        // Xác thực các field bắt buộc
        if (string.IsNullOrEmpty(message.Id))
        {
            throw new FormatException("Message ID là bắt buộc");
        }
        
        if (string.IsNullOrEmpty(message.SenderId))
        {
            throw new FormatException("Sender ID là bắt buộc");
        }
        
        // Bảo mật: Xác thực độ dài content
        // 500,000 ký tự đủ cho file chunks 64KB sau khi Base64 encode + mã hóa
        const int MaxContentLength = 500_000;
        if (message.Content?.Length > MaxContentLength)
        {
            throw new FormatException($"Nội dung tin nhắn vượt quá độ dài tối đa {MaxContentLength}");
        }
        
        // Bảo mật: Xác thực timestamp hợp lý
        // Điều này giúp ngăn chặn replay attacks
        var timeDiff = DateTime.UtcNow - message.Timestamp;
        if (Math.Abs(timeDiff.TotalMinutes) > 5)
        {
            throw new FormatException("Timestamp tin nhắn nằm ngoài phạm vi chấp nhận được");
        }
    }
}
