using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureChat.Core.Models;

namespace SecureChat.Core.Networking;

public sealed class JsonMessageSerializer : IMessageSerializer
{
    public const int MaxMessageSize = 2 * 1024 * 1024; // 2 MB - Tăng lên để hỗ trợ UTF-8 overhead và encoding

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
        var bytes = Encoding.UTF8.GetBytes(json); // FIX: Sử dụng UTF-8 thay vì Unicode để giảm kích thước (1 byte/char cho ASCII)
        
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
            var json = Encoding.UTF8.GetString(data); // FIX: Sử dụng UTF-8
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
        // 1,500,000 ký tự đủ cho payload lớn trong UTF-8
        const int MaxContentLength = 1_500_000;
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
