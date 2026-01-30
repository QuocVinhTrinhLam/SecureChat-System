using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using SecureChat.Client;
using SecureChat.Core.Models;
using SecureChat.Core.Utilities;
using SecureChat.AvaloniaClient.Models;

namespace SecureChat.AvaloniaClient.Services;

public class ChatService : IDisposable
{
    private ServerConnection? _connection;
    private CancellationTokenSource? _cts;
    private Task? _receiveTask;
    private readonly AvaloniaLogger _logger;
    private bool _disposed;
    private string _userId = string.Empty;
    private string _userName = string.Empty;
    
    public string UserName => _userName;
    
    public event EventHandler<Message>? MessageReceived;
    
    public event EventHandler<ConnectionState>? ConnectionStateChanged;
    
    public event EventHandler<string>? ErrorOccurred;
    
    public bool IsConnected { get; private set; }
    
    public ChatService()
    {
        _logger = new AvaloniaLogger();
    }
    
    public async Task ConnectAsync(string host, int port, string username)
    {
        if (IsConnected)
        {
            throw new InvalidOperationException("Đã kết nối rồi");
        }
        
        try
        {
            RaiseConnectionStateChanged(ConnectionState.Connecting);
            
            _userId = Guid.NewGuid().ToString();
            _userName = username;
            _cts = new CancellationTokenSource();
            _connection = new ServerConnection(host, port, _logger);
            
            // Kết nối TCP
            await _connection.ConnectAsync(_cts.Token);
            
            // Thực hiện key exchange
            await _connection.PerformKeyExchangeAsync(_userId, _userName, _cts.Token);
            
            // Subscribe to message events
            _connection.MessageReceived += OnServerConnectionMessageReceived;
            
            Console.WriteLine("[ChatService] Starting receive loop...");
            
            // Bắt đầu receive loop trong background
            _receiveTask = _connection.StartReceivingAsync(_cts.Token);
            
            Console.WriteLine("[ChatService] Receive loop started");
            
            // Gửi tin nhắn join
            var joinMessage = Message.CreateJoinMessage(_userId, _userName);
            await _connection.SendMessageAsync(joinMessage, _cts.Token);
            
            Console.WriteLine("[ChatService] Join message sent");
            
            IsConnected = true;
            RaiseConnectionStateChanged(ConnectionState.Connected);
        }
        catch (Exception ex)
        {
            IsConnected = false;
            RaiseConnectionStateChanged(ConnectionState.Error);
            RaiseError($"Không thể kết nối: {ex.Message}");
            throw;
        }
    }
    
    public async Task DisconnectAsync()
    {
        if (!IsConnected)
        {
            return;
        }
        
        try
        {
            RaiseConnectionStateChanged(ConnectionState.Disconnecting);
            
            // Gửi tin nhắn leave
            if (_connection != null)
            {
                try
                {
                    var leaveMessage = Message.CreateLeaveMessage(_userId, _userName);
                    await _connection.SendMessageAsync(leaveMessage, CancellationToken.None);
                }
                catch
                {
                    // Ignore errors when disconnecting
                }
            }
            
            _cts?.Cancel();
            
            if (_receiveTask != null)
            {
                try
                {
                    await _receiveTask;
                }
                catch (OperationCanceledException)
                {
                    // Expected
                }
            }
            
            IsConnected = false;
            RaiseConnectionStateChanged(ConnectionState.Disconnected);
        }
        catch (Exception ex)
        {
            RaiseError($"Lỗi khi ngắt kết nối: {ex.Message}");
        }
    }
    
    public async Task<Message> SendMessageAsync(string content, string? recipientName = null)
    {
        if (!IsConnected || _connection == null)
        {
            throw new InvalidOperationException("Chưa kết nối");
        }
        
        try
        {
            Message message;
            
            if (!string.IsNullOrEmpty(recipientName))
            {
                // Tin nhắn trực tiếp
                message = Message.CreateDirectMessage(
                    _userId, _userName,
                    recipientName, recipientName,
                    content);
                Console.WriteLine($"[ChatService] Sending direct message to {recipientName}: {content}");
            }
            else
            {
                // Tin nhắn broadcast
                message = Message.CreateTextMessage(_userId, _userName, content);
                Console.WriteLine($"[ChatService] Sending broadcast message: {content}");
            }
            
            await _connection.SendMessageAsync(message, _cts?.Token ?? CancellationToken.None);
            Console.WriteLine($"[ChatService] Message sent successfully");
            
            return message;
        }
        catch (Exception ex)
        {
            RaiseError($"Lỗi gửi tin nhắn: {ex.Message}");
            throw;
        }
    }
    
    public async Task SendFileMetadataAsync(FileMetadata metadata, string recipientName)
    {
        if (!IsConnected || _connection == null)
        {
            throw new InvalidOperationException("Chưa kết nối");
        }
        
        var message = Message.CreateFileMessage(
            _userId, _userName,
            recipientName, recipientName,
            metadata);
        
        Console.WriteLine($"[ChatService] Sending file metadata: {metadata.FileName} to {recipientName}");
        await _connection.SendMessageAsync(message, _cts?.Token ?? CancellationToken.None);
    }
    
    public async Task SendFileChunkAsync(FileChunkData chunkData, string recipientName)
    {
        if (!IsConnected || _connection == null)
        {
            throw new InvalidOperationException("Chưa kết nối");
        }
        
        var message = Message.CreateFileChunkMessage(
            _userId, _userName,
            recipientName, recipientName,
            chunkData);
        
        await _connection.SendMessageAsync(message, _cts?.Token ?? CancellationToken.None);
    }
    
    public async Task SendFileCompleteAsync(string fileId, string fileName, string recipientName)
    {
        if (!IsConnected || _connection == null)
        {
            throw new InvalidOperationException("Chưa kết nối");
        }
        
        var message = Message.CreateFileCompleteMessage(
            _userId, _userName,
            recipientName, recipientName,
            fileId, fileName);
        
        Console.WriteLine($"[ChatService] Sending file complete: {fileName} to {recipientName}");
        await _connection.SendMessageAsync(message, _cts?.Token ?? CancellationToken.None);
    }
    
    private void OnServerConnectionMessageReceived(object? sender, Message message)
    {
        Console.WriteLine($"[ChatService] OnServerConnectionMessageReceived: Type={message.Type}, Sender={message.SenderName}, Content={message.Content}");
        
        // Dispatch lên UI thread
        Dispatcher.UIThread.Post(() =>
        {
            Console.WriteLine($"[ChatService] Dispatched to UI thread: Type={message.Type}");
            MessageReceived?.Invoke(this, message);
        });
    }
    
    private void RaiseConnectionStateChanged(ConnectionState state)
    {
        Dispatcher.UIThread.Post(() =>
        {
            ConnectionStateChanged?.Invoke(this, state);
        });
    }
    
    private void RaiseError(string error)
    {
        Dispatcher.UIThread.Post(() =>
        {
            ErrorOccurred?.Invoke(this, error);
        });
    }
    
    public void Dispose()
    {
        if (_disposed) return;
        
        _cts?.Cancel();
        _cts?.Dispose();
        _connection?.Dispose();
        _disposed = true;
    }
}

internal class AvaloniaLogger : ILogger
{
    public event EventHandler<string>? LogMessageReceived;
    
    public LogLevel MinimumLevel { get; set; } = LogLevel.Debug;
    
    public void Log(LogLevel level, string message, params object[] args)
    {
        if (level < MinimumLevel) return;
        
        var formatted = string.Format(message, args);
        var prefix = level switch
        {
            LogLevel.Debug => "[DEBUG]",
            LogLevel.Info => "[INFO]",
            LogLevel.Warning => "[WARNING]",
            LogLevel.Error => "[ERROR]",
            LogLevel.Security => "[SECURITY]",
            _ => "[LOG]"
        };
        
        System.Diagnostics.Debug.WriteLine($"{prefix} {formatted}");
        LogMessageReceived?.Invoke(this, formatted);
    }
    
    public void Debug(string message, params object[] args)
    {
        Log(LogLevel.Debug, message, args);
    }
    
    public void Info(string message, params object[] args)
    {
        Log(LogLevel.Info, message, args);
    }
    
    public void Warning(string message, params object[] args)
    {
        Log(LogLevel.Warning, message, args);
    }
    
    public void Error(string message, params object[] args)
    {
        Log(LogLevel.Error, message, args);
    }
    
    public void Security(string message, params object[] args)
    {
        Log(LogLevel.Security, message, args);
    }
    
    public void Exception(Exception ex, string message)
    {
        var formatted = $"{message}: {ex.Message}\n{ex.StackTrace}";
        System.Diagnostics.Debug.WriteLine($"[EXCEPTION] {formatted}");
        LogMessageReceived?.Invoke(this, $"{message}: {ex.Message}");
    }
}
