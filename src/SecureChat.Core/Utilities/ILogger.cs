namespace SecureChat.Core.Utilities;

/// <summary>
/// Các mức độ log cho logging bảo mật và vận hành.
/// </summary>
public enum LogLevel
{
    /// <summary>Thông tin debug chi tiết.</summary>
    Debug = 0,
    
    /// <summary>Tin nhắn thông tin chung.</summary>
    Info = 1,
    
    /// <summary>Điều kiện cảnh báo có thể cần chú ý.</summary>
    Warning = 2,
    
    /// <summary>Điều kiện lỗi ảnh hưởng đến chức năng.</summary>
    Error = 3,
    
    /// <summary>
    /// Sự kiện liên quan đến bảo mật
    /// Các sự kiện này luôn được log bất kể cài đặt log level.
    /// </summary>
    Security = 4
}

/// <summary>
/// Abstraction cho logging trong toàn ứng dụng.
/// 
/// Thiết kế bảo mật:
/// - Tách riêng logging khỏi implementation để linh hoạt
/// - Security-level events cho audit trail
/// - Hỗ trợ structured logging cho phân tích
/// 
/// Best practices bảo mật:
/// - Không bao giờ log dữ liệu nhạy cảm
/// - Log các sự kiện liên quan đến bảo mật
/// - Bao gồm correlation IDs để theo dõi các sự kiện liên quan
/// - Timestamp tất cả entries theo UTC
/// </summary>
public interface ILogger
{
    /// <summary>
    /// Log tin nhắn ở mức được chỉ định.
    /// </summary>
    /// <param name="level">Mức độ nghiêm trọng của log entry.</param>
    /// <param name="message">Tin nhắn log.</param>
    /// <param name="args">Các đối số format tùy chọn.</param>
    void Log(LogLevel level, string message, params object[] args);
    
    /// <summary>
    /// Log tin nhắn debug
    /// </summary>
    void Debug(string message, params object[] args);
    
    /// <summary>
    /// Log tin nhắn thông tin
    /// </summary>
    void Info(string message, params object[] args);
    
    /// <summary>
    /// Log tin nhắn cảnh báo
    /// </summary>
    void Warning(string message, params object[] args);
    
    /// <summary>
    /// Log tin nhắn lỗi
    /// </summary>
    void Error(string message, params object[] args);
    
    /// <summary>
    /// Log sự kiện liên quan đến bảo mật
    /// Bảo mật: Các sự kiện này luôn được log cho mục đích audit
    /// </summary>
    void Security(string message, params object[] args);
    
    /// <summary>
    /// Log exception với ngữ cảnh
    /// Bảo mật: Chi tiết exception có thể nhạy cảm - log phù hợp
    /// </summary>
    void Exception(Exception ex, string context);
    
    /// <summary>
    /// Lấy hoặc đặt mức log tối thiểu để xuất
    /// Security events luôn được log bất kể cài đặt này
    /// </summary>
    LogLevel MinimumLevel { get; set; }
}
