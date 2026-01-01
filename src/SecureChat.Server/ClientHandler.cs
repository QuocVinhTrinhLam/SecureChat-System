using System.Net.Sockets;
using SecureChat.Core.Models;
using SecureChat.Core.Networking;
using SecureChat.Core.Utilities;

namespace SecureChat.Server;

/// <summary>
/// Handles communication with a single connected client.
/// 
/// Security Design:
/// - Isolated per-client processing prevents cross-client interference
/// - Message framing using length-prefix prevents injection attacks
/// - Input validation before processing
/// - Future: Will integrate with security providers for encryption
/// 
/// Wire Protocol:
/// Each message is prefixed with its length as a 4-byte big-endian integer.
/// [4 bytes: length][N bytes: JSON message]
/// </summary>
public sealed class ClientHandler : IDisposable
{
    private readonly TcpClient _tcpClient;
    private readonly ClientManager _clientManager;
    private readonly IMessageSerializer _serializer;
    private readonly ILogger _logger;
    private readonly NetworkStream _stream;
    private readonly User _user;
    private readonly string _clientEndpoint;
    private bool _disposed;
    
    /// <summary>
    /// Gets the user associated with this client handler.
    /// </summary>
    public User User => _user;
    
    /// <summary>
    /// Creates a new client handler.
    /// </summary>
    public ClientHandler(
        TcpClient tcpClient, 
        ClientManager clientManager,
        IMessageSerializer serializer,
        ILogger logger)
    {
        _tcpClient = tcpClient;
        _clientManager = clientManager;
        _serializer = serializer;
        _logger = logger;
        _stream = tcpClient.GetStream();
        _user = new User { Username = "Unknown" };
        _clientEndpoint = tcpClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
        
        // Configure socket options for better behavior
        ConfigureSocket();
    }
    
    /// <summary>
    /// Configures socket options for security and performance.
    /// </summary>
    private void ConfigureSocket()
    {
        // Disable Nagle's algorithm for lower latency
        _tcpClient.NoDelay = true;
        
        // Set reasonable timeouts to prevent resource exhaustion
        _tcpClient.ReceiveTimeout = 30000; // 30 seconds
        _tcpClient.SendTimeout = 10000;    // 10 seconds
        
        // Security: Limit receive buffer to prevent memory exhaustion
        _tcpClient.ReceiveBufferSize = JsonMessageSerializer.MaxMessageSize;
    }
    
    /// <summary>
    /// Main processing loop for this client.
    /// </summary>
    public async Task ProcessAsync(CancellationToken cancellationToken)
    {
        try
        {
            // Wait for the first message (should be Join)
            var firstMessage = await ReceiveMessageAsync(cancellationToken);
            
            if (firstMessage is null || firstMessage.Type != MessageType.Join)
            {
                _logger.Warning("Client {0} did not send Join message first", _clientEndpoint);
                await SendErrorAsync("First message must be a Join message");
                return;
            }
            
            // Validate and set username
            _user.Id = firstMessage.SenderId;
            _user.Username = SanitizeUsername(firstMessage.SenderName);
            
            // Register with client manager
            _clientManager.AddClient(this);
            
            _logger.Info("User '{0}' joined from {1}", _user.Username, _clientEndpoint);
            _logger.Security("User joined: {0} (ID: {1})", _user.Username, _user.Id);
            
            // Broadcast join notification to all clients
            await _clientManager.BroadcastAsync(
                Message.CreateJoinMessage(_user.Id, _user.Username),
                cancellationToken);
            
            // Main message processing loop
            while (!cancellationToken.IsCancellationRequested)
            {
                var message = await ReceiveMessageAsync(cancellationToken);
                
                if (message is null)
                {
                    // Client disconnected
                    break;
                }
                
                await ProcessMessageAsync(message, cancellationToken);
            }
        }
        catch (IOException)
        {
            // Client disconnected abruptly
            _logger.Debug("Client {0} disconnected (IO)", _clientEndpoint);
        }
        catch (OperationCanceledException)
        {
            // Server shutdown
            throw;
        }
        catch (Exception ex)
        {
            _logger.Exception(ex, $"Error processing client {_clientEndpoint}");
        }
        finally
        {
            await HandleDisconnectAsync(cancellationToken);
        }
    }
    
    /// <summary>
    /// Processes a received message based on its type.
    /// </summary>
    private async Task ProcessMessageAsync(Message message, CancellationToken cancellationToken)
    {
        // Security: Validate sender matches this client
        if (message.SenderId != _user.Id)
        {
            _logger.Security("Sender ID mismatch from {0}: expected {1}, got {2}", 
                _clientEndpoint, _user.Id, message.SenderId);
            await SendErrorAsync("Sender ID does not match session");
            return;
        }
        
        switch (message.Type)
        {
            case MessageType.Text:
                // Broadcast text message to all clients
                _logger.Debug("Message from {0}: {1}", _user.Username, 
                    TruncateForLog(message.Content));
                await _clientManager.BroadcastAsync(message, cancellationToken);
                break;
                
            case MessageType.Leave:
                // Client is gracefully disconnecting
                _logger.Info("User '{0}' is leaving", _user.Username);
                return; // Will trigger disconnect handling
                
            case MessageType.KeyExchange:
                // Placeholder for future key exchange implementation
                _logger.Security("Key exchange requested by {0} (not implemented)", _user.Username);
                await SendErrorAsync("Key exchange not implemented in foundation phase");
                break;
                
            default:
                _logger.Warning("Unknown message type {0} from {1}", message.Type, _user.Username);
                await SendErrorAsync($"Unknown message type: {message.Type}");
                break;
        }
    }
    
    /// <summary>
    /// Handles client disconnection.
    /// </summary>
    private async Task HandleDisconnectAsync(CancellationToken cancellationToken)
    {
        _clientManager.RemoveClient(_user.Id);
        
        if (_user.Username != "Unknown")
        {
            _logger.Info("User '{0}' disconnected", _user.Username);
            _logger.Security("User disconnected: {0} (ID: {1})", _user.Username, _user.Id);
            
            // Notify other clients
            try
            {
                await _clientManager.BroadcastAsync(
                    Message.CreateLeaveMessage(_user.Id, _user.Username),
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // Ignore during shutdown
            }
        }
    }
    
    /// <summary>
    /// Receives a length-prefixed message from the client.
    /// </summary>
    private async Task<Message?> ReceiveMessageAsync(CancellationToken cancellationToken)
    {
        // Read message length (4 bytes, big-endian)
        var lengthBuffer = new byte[4];
        var bytesRead = await ReadExactAsync(lengthBuffer, cancellationToken);
        
        if (bytesRead < 4)
        {
            return null; // Client disconnected
        }
        
        // Convert from big-endian
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(lengthBuffer);
        }
        var messageLength = BitConverter.ToInt32(lengthBuffer, 0);
        
        // Security: Validate message length
        if (messageLength <= 0 || messageLength > JsonMessageSerializer.MaxMessageSize)
        {
            _logger.Security("Invalid message length {0} from {1}", messageLength, _clientEndpoint);
            throw new InvalidOperationException($"Invalid message length: {messageLength}");
        }
        
        // Read message body
        var messageBuffer = new byte[messageLength];
        bytesRead = await ReadExactAsync(messageBuffer, cancellationToken);
        
        if (bytesRead < messageLength)
        {
            return null; // Client disconnected mid-message
        }
        
        try
        {
            return _serializer.Deserialize(messageBuffer);
        }
        catch (FormatException ex)
        {
            _logger.Warning("Invalid message format from {0}: {1}", _clientEndpoint, ex.Message);
            await SendErrorAsync("Invalid message format");
            throw;
        }
    }
    
    /// <summary>
    /// Reads exactly the requested number of bytes from the stream.
    /// </summary>
    private async Task<int> ReadExactAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await _stream.ReadAsync(
                buffer.AsMemory(totalRead, buffer.Length - totalRead), 
                cancellationToken);
            
            if (read == 0)
            {
                break; // End of stream
            }
            totalRead += read;
        }
        return totalRead;
    }
    
    /// <summary>
    /// Sends a message to this client.
    /// </summary>
    public async Task SendMessageAsync(Message message, CancellationToken cancellationToken)
    {
        if (_disposed) return;
        
        try
        {
            var messageBytes = _serializer.Serialize(message);
            
            // Create length prefix (big-endian)
            var lengthBytes = BitConverter.GetBytes(messageBytes.Length);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(lengthBytes);
            }
            
            // Write length + message atomically
            await _stream.WriteAsync(lengthBytes, cancellationToken);
            await _stream.WriteAsync(messageBytes, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Client disconnected
            _logger.Debug("Send failed to {0}: {1}", _clientEndpoint, ex.Message);
        }
    }
    
    /// <summary>
    /// Sends an error message to the client.
    /// </summary>
    private async Task SendErrorAsync(string errorMessage)
    {
        var error = new Message
        {
            Type = MessageType.Error,
            SenderId = "SERVER",
            SenderName = "Server",
            Content = errorMessage
        };
        
        await SendMessageAsync(error, CancellationToken.None);
    }
    
    /// <summary>
    /// Sanitizes username to prevent injection attacks.
    /// </summary>
    private static string SanitizeUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return "Anonymous";
        }
        
        // Remove potentially dangerous characters
        // Security: In production, use a proper sanitization library
        var sanitized = username
            .Replace("<", "")
            .Replace(">", "")
            .Replace("&", "")
            .Trim();
        
        // Limit length
        const int MaxLength = 32;
        if (sanitized.Length > MaxLength)
        {
            sanitized = sanitized[..MaxLength];
        }
        
        return string.IsNullOrWhiteSpace(sanitized) ? "Anonymous" : sanitized;
    }
    
    /// <summary>
    /// Truncates message content for safe logging.
    /// </summary>
    private static string TruncateForLog(string content)
    {
        const int MaxLogLength = 50;
        if (content.Length <= MaxLogLength)
        {
            return content;
        }
        return content[..MaxLogLength] + "...";
    }
    
    /// <summary>
    /// Disposes client resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        _stream.Dispose();
        _tcpClient.Dispose();
        _disposed = true;
    }
}
