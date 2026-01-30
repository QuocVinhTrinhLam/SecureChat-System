namespace SecureChat.Core.Utilities;

public enum LogLevel
{
    Debug = 0,
    
    Info = 1,
    
    Warning = 2,
    
    Error = 3,
    
    Security = 4
}

public interface ILogger
{
    void Log(LogLevel level, string message, params object[] args);
    
    void Debug(string message, params object[] args);
    
    void Info(string message, params object[] args);
    
    void Warning(string message, params object[] args);
    
    void Error(string message, params object[] args);
    
    void Security(string message, params object[] args);
    
    void Exception(Exception ex, string context);
    
    LogLevel MinimumLevel { get; set; }
}
