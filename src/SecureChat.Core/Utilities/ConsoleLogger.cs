namespace SecureChat.Core.Utilities;

/// <summary>
/// Thread-safe console logger implementation.
/// Suitable for development and debugging; consider file-based or 
/// structured logging for production deployments.
/// </summary>
public sealed class ConsoleLogger : ILogger
{
    private static readonly object LockObject = new();
    
    /// <inheritdoc />
    public LogLevel MinimumLevel { get; set; } = LogLevel.Info;
    
    /// <summary>
    /// Creates a new console logger with the specified minimum level.
    /// </summary>
    /// <param name="minimumLevel">Minimum log level to display.</param>
    public ConsoleLogger(LogLevel minimumLevel = LogLevel.Info)
    {
        MinimumLevel = minimumLevel;
    }
    
    /// <inheritdoc />
    public void Log(LogLevel level, string message, params object[] args)
    {
        // Security events are always logged
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
        // Security: Log exception type and message, but be careful
        // not to log sensitive data that might be in the exception
        Log(LogLevel.Error, "{0}: {1} - {2}", context, ex.GetType().Name, ex.Message);
        
        // Only log stack trace in debug mode
        if (MinimumLevel == LogLevel.Debug)
        {
            Log(LogLevel.Debug, "Stack trace: {0}", ex.StackTrace ?? "Not available");
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
