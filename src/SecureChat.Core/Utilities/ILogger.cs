namespace SecureChat.Core.Utilities;

/// <summary>
/// Log severity levels for security and operational logging.
/// </summary>
public enum LogLevel
{
    /// <summary>Detailed debugging information.</summary>
    Debug = 0,
    
    /// <summary>General informational messages.</summary>
    Info = 1,
    
    /// <summary>Warning conditions that may require attention.</summary>
    Warning = 2,
    
    /// <summary>Error conditions that affect functionality.</summary>
    Error = 3,
    
    /// <summary>
    /// Security-relevant events (authentication, access control, etc.).
    /// These should always be logged regardless of log level setting.
    /// </summary>
    Security = 4
}

/// <summary>
/// Abstraction for logging throughout the application.
/// 
/// Security Design:
/// - Separates logging from implementation for flexibility
/// - Security-level events for audit trail
/// - Structured logging support for analysis
/// 
/// Security Best Practices:
/// - Never log sensitive data (keys, passwords, full messages)
/// - Log security-relevant events (auth attempts, key exchanges, errors)
/// - Include correlation IDs for tracking related events
/// - Timestamp all entries in UTC
/// </summary>
public interface ILogger
{
    /// <summary>
    /// Logs a message at the specified level.
    /// </summary>
    /// <param name="level">The severity level of the log entry.</param>
    /// <param name="message">The log message.</param>
    /// <param name="args">Optional format arguments.</param>
    void Log(LogLevel level, string message, params object[] args);
    
    /// <summary>
    /// Logs a debug message.
    /// </summary>
    void Debug(string message, params object[] args);
    
    /// <summary>
    /// Logs an informational message.
    /// </summary>
    void Info(string message, params object[] args);
    
    /// <summary>
    /// Logs a warning message.
    /// </summary>
    void Warning(string message, params object[] args);
    
    /// <summary>
    /// Logs an error message.
    /// </summary>
    void Error(string message, params object[] args);
    
    /// <summary>
    /// Logs a security-relevant event.
    /// Security: These events should always be logged for audit purposes.
    /// </summary>
    void Security(string message, params object[] args);
    
    /// <summary>
    /// Logs an exception with context.
    /// Security: Exception details may be sensitive - log appropriately.
    /// </summary>
    void Exception(Exception ex, string context);
    
    /// <summary>
    /// Gets or sets the minimum log level to output.
    /// Security events are always logged regardless of this setting.
    /// </summary>
    LogLevel MinimumLevel { get; set; }
}
