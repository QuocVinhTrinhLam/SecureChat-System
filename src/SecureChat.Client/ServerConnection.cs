using System.Net.Sockets;
using SecureChat.Core.Models;
using SecureChat.Core.Networking;
using SecureChat.Core.Utilities;

namespace SecureChat.Client;

/// <summary>
/// Manages the TCP connection to the chat server.
/// 
/// Security Design:
/// - Length-prefixed framing matches server protocol
/// - Prepared for future TLS integration
/// - Clean separation from UI concerns
/// 
/// Future Enhancements:
/// - Reconnection logic with exponential backoff
/// - TLS/SSL for transport security
/// - Certificate validation
/// </summary>
public sealed class ServerConnection : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly ILogger _logger;
    private readonly IMessageSerializer _serializer;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private bool _disposed;
    
    /// <summary>
    /// Event raised when a message is received from the server.
    /// </summary>
    public event EventHandler<Message>? MessageReceived;
    
    /// <summary>
    /// Creates a new server connection.
    /// </summary>
    /// <param name="host">Server hostname.</param>
    /// <param name="port">Server port.</param>
    /// <param name="logger">Logger for events.</param>
    public ServerConnection(string host, int port, ILogger logger)
    {
        _host = host;
        _port = port;
        _logger = logger;
        _serializer = new JsonMessageSerializer();
    }
    
    /// <summary>
    /// Connects to the server.
    /// </summary>
    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        _client = new TcpClient();
        
        // Configure socket options
        _client.NoDelay = true;
        _client.ReceiveTimeout = 30000;
        _client.SendTimeout = 10000;
        
        try
        {
            await _client.ConnectAsync(_host, _port, cancellationToken);
            _stream = _client.GetStream();
            
            _logger.Security("TCP connection established to {0}:{1}", _host, _port);
            _logger.Warning("Connection is NOT encrypted - foundation phase only");
        }
        catch (SocketException ex)
        {
            _logger.Error("Failed to connect: {0}", ex.Message);
            throw;
        }
    }
    
    /// <summary>
    /// Starts receiving messages in a loop.
    /// </summary>
    public async Task StartReceivingAsync(CancellationToken cancellationToken)
    {
        if (_stream is null)
        {
            throw new InvalidOperationException("Not connected");
        }
        
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var message = await ReceiveMessageAsync(cancellationToken);
                
                if (message is null)
                {
                    _logger.Info("Server closed connection");
                    break;
                }
                
                MessageReceived?.Invoke(this, message);
            }
            catch (IOException)
            {
                _logger.Warning("Connection lost");
                break;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.Exception(ex, "Error receiving message");
            }
        }
    }
    
    /// <summary>
    /// Receives a length-prefixed message from the server.
    /// </summary>
    private async Task<Message?> ReceiveMessageAsync(CancellationToken cancellationToken)
    {
        if (_stream is null) return null;
        
        // Read message length (4 bytes, big-endian)
        var lengthBuffer = new byte[4];
        var bytesRead = await ReadExactAsync(lengthBuffer, cancellationToken);
        
        if (bytesRead < 4)
        {
            return null; // Server disconnected
        }
        
        // Convert from big-endian
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(lengthBuffer);
        }
        var messageLength = BitConverter.ToInt32(lengthBuffer, 0);
        
        // Validate message length
        if (messageLength <= 0 || messageLength > JsonMessageSerializer.MaxMessageSize)
        {
            _logger.Warning("Invalid message length: {0}", messageLength);
            return null;
        }
        
        // Read message body
        var messageBuffer = new byte[messageLength];
        bytesRead = await ReadExactAsync(messageBuffer, cancellationToken);
        
        if (bytesRead < messageLength)
        {
            return null;
        }
        
        return _serializer.Deserialize(messageBuffer);
    }
    
    /// <summary>
    /// Reads exactly the requested number of bytes.
    /// </summary>
    private async Task<int> ReadExactAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        if (_stream is null) return 0;
        
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await _stream.ReadAsync(
                buffer.AsMemory(totalRead, buffer.Length - totalRead),
                cancellationToken);
            
            if (read == 0)
            {
                break;
            }
            totalRead += read;
        }
        return totalRead;
    }
    
    /// <summary>
    /// Sends a message to the server.
    /// </summary>
    public async Task SendMessageAsync(Message message, CancellationToken cancellationToken)
    {
        if (_stream is null)
        {
            throw new InvalidOperationException("Not connected");
        }
        
        var messageBytes = _serializer.Serialize(message);
        
        // Create length prefix (big-endian)
        var lengthBytes = BitConverter.GetBytes(messageBytes.Length);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(lengthBytes);
        }
        
        // Write length + message
        await _stream.WriteAsync(lengthBytes, cancellationToken);
        await _stream.WriteAsync(messageBytes, cancellationToken);
        await _stream.FlushAsync(cancellationToken);
    }
    
    /// <summary>
    /// Disposes connection resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        _stream?.Dispose();
        _client?.Dispose();
        _disposed = true;
    }
}
