namespace SecureChat.Core.Utilities;

/// <summary>
/// Implementation console logger thread-safe.
/// Phù hợp cho phát triển và debug; cân nhắc file-based hoặc 
/// structured logging cho môi trường production.
/// </summary>
public sealed class ConsoleLogger : ILogger
{
    private static readonly object LockObject = new();
    
    /// <inheritdoc />
    public LogLevel MinimumLevel { get; set; } = LogLevel.Info;
    
    /// <summary>
    /// Tạo console logger mới với mức tối thiểu được chỉ định.
    /// </summary>
    /// <param name="minimumLevel">Mức log tối thiểu để hiển thị.</param>
    public ConsoleLogger(LogLevel minimumLevel = LogLevel.Info)
    {
        MinimumLevel = minimumLevel;
    }
    
    /// <inheritdoc />
    public void Log(LogLevel level, string message, params object[] args)
    {
        // Security events luôn được log
        if (level != LogLevel.Security && level < MinimumLevel)
        {
            return;
        }
        
        var formattedMessage = args.Length > 0 
            ? string.Format(message, args) 
            : message;
        
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var levelString = GetLevelString(level);
        var color = GetLevelColor(level);
        
        // Thread-safe console output
        lock (LockObject)
        {
            var originalColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine($"[{timestamp}] [{levelString}] {formattedMessage}");
            Console.ForegroundColor = originalColor;
        }
    }
    
    /// <inheritdoc />
    public void Debug(string message, params object[] args) 
        => Log(LogLevel.Debug, message, args);
    
    /// <inheritdoc />
    public void Info(string message, params object[] args) 
        => Log(LogLevel.Info, message, args);
    
    /// <inheritdoc />
    public void Warning(string message, params object[] args) 
        => Log(LogLevel.Warning, message, args);
    
    /// <inheritdoc />
    public void Error(string message, params object[] args) 
        => Log(LogLevel.Error, message, args);
    
    /// <inheritdoc />
    public void Security(string message, params object[] args) 
        => Log(LogLevel.Security, message, args);
    
    /// <inheritdoc />
    public void Exception(Exception ex, string context)
    {
        // Bảo mật: Log loại và message exception, nhưng cẩn thận
        // không log dữ liệu nhạy cảm có thể có trong exception
        Log(LogLevel.Error, "{0}: {1} - {2}", context, ex.GetType().Name, ex.Message);
        
        // Chỉ log stack trace trong chế độ debug
        if (MinimumLevel == LogLevel.Debug)
        {
            Log(LogLevel.Debug, "Stack trace: {0}", ex.StackTrace ?? "Không có");
        }
    }
    
    private static string GetLevelString(LogLevel level) => level switch
    {
        LogLevel.Debug => "DEBUG",
        LogLevel.Info => "INFO ",
        LogLevel.Warning => "WARN ",
        LogLevel.Error => "ERROR",
        LogLevel.Security => "SECUR",
        _ => "UNKN "
    };
    
    private static ConsoleColor GetLevelColor(LogLevel level) => level switch
    {
        LogLevel.Debug => ConsoleColor.Gray,
        LogLevel.Info => ConsoleColor.White,
        LogLevel.Warning => ConsoleColor.Yellow,
        LogLevel.Error => ConsoleColor.Red,
        LogLevel.Security => ConsoleColor.Magenta,
        _ => ConsoleColor.White
    };
}
