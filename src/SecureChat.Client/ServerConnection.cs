using System.Net.Sockets;
using SecureChat.Core.Models;
using SecureChat.Core.Networking;
using SecureChat.Core.Security.Implementations;
using SecureChat.Core.Utilities;

namespace SecureChat.Client;

/// <summary>
/// Manages the TCP connection to the chat server with secure session support.
/// 
/// Security Design:
/// - Length-prefixed framing matches server protocol
/// - ECDH key exchange establishes secure session
/// - AES-256-GCM encryption after key exchange
/// </summary>
public sealed class ServerConnection : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly ILogger _logger;
    private readonly IMessageSerializer _serializer;
    private readonly SecureSession _session;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private bool _disposed;
    
    /// <summary>
    /// Gets whether secure session is established.
    /// </summary>
    public bool IsSecure => _session.IsEstablished;
    
    /// <summary>
    /// Event raised when a message is received from the server.
    /// </summary>
    public event EventHandler<Message>? MessageReceived;
    
    /// <summary>
    /// Creates a new server connection.
    /// </summary>
    public ServerConnection(string host, int port, ILogger logger)
    {
        _host = host;
        _port = port;
        _logger = logger;
        _serializer = new JsonMessageSerializer();
        _session = new SecureSession();
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
            
            // Initialize secure session
            await _session.InitializeAsync();
            _logger.Security("Secure session initialized (ECDH keys generated)");
        }
        catch (SocketException ex)
        {
            _logger.Error("Failed to connect: {0}", ex.Message);
            throw;
        }
    }
    
    /// <summary>
    /// Performs key exchange with the server.
    /// </summary>
    /// <param name="userId">Client user ID</param>
    /// <param name="userName">Client username</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task PerformKeyExchangeAsync(string userId, string userName, CancellationToken cancellationToken)
    {
        _logger.Info("Đang thực hiện trao đổi khóa với server...");
        
        // Send our public key to server
        var clientKeyMessage = _session.GetKeyExchangeMessage(userId, userName);
        await SendRawMessageAsync(clientKeyMessage, cancellationToken);
        _logger.Security("Đã gửi khóa công khai đến server");
        
        // Wait for server's KeyExchange response (may receive System messages first)
        Message? serverKeyMessage = null;
        while (serverKeyMessage == null || serverKeyMessage.Type != MessageType.KeyExchange)
        {
            serverKeyMessage = await ReceiveRawMessageAsync(cancellationToken);
            
            if (serverKeyMessage == null)
            {
                throw new InvalidOperationException("Server đã ngắt kết nối");
            }
            
            // Display system/error messages but keep waiting for KeyExchange
            if (serverKeyMessage.Type == MessageType.System)
            {
                _logger.Info("[Server]: {0}", serverKeyMessage.Content);
            }
            else if (serverKeyMessage.Type == MessageType.Error)
            {
                _logger.Error("[Server Error]: {0}", serverKeyMessage.Content);
                throw new InvalidOperationException(serverKeyMessage.Content);
            }
            else if (serverKeyMessage.Type != MessageType.KeyExchange)
            {
                _logger.Warning("Nhận tin nhắn loại {0} trong quá trình key exchange", serverKeyMessage.Type);
            }
        }
        
        // Process server's key to establish session
        await _session.ProcessKeyExchangeMessageAsync(serverKeyMessage);
        
        _logger.Security("✓ Phiên bảo mật đã thiết lập! (AES-256-GCM)");
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
                var message = await ReceiveRawMessageAsync(cancellationToken);
                
                if (message is null)
                {
                    _logger.Info("Server closed connection");
                    break;
                }
                
                // If encrypted and session is established, decrypt
                if (message.Type == MessageType.Encrypted && _session.IsEstablished)
                {
                    try
                    {
                        var decrypted = await _session.DecryptMessageAsync(message);
                        MessageReceived?.Invoke(this, decrypted);
                    }
                    catch (Exception ex)
                    {
                        _logger.Error("Lỗi giải mã: {0}", ex.Message);
                    }
                }
                else
                {
                    MessageReceived?.Invoke(this, message);
                }
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
    /// Receives a raw length-prefixed message from the server.
    /// </summary>
    private async Task<Message?> ReceiveRawMessageAsync(CancellationToken cancellationToken)
    {
        if (_stream is null) return null;
        
        // Read message length (4 bytes, big-endian)
        var lengthBuffer = new byte[4];
        var bytesRead = await ReadExactAsync(lengthBuffer, cancellationToken);
        
        if (bytesRead < 4)
        {
            return null; // Server disconnected
        }
        
        _logger.Debug("Raw length bytes: [{0:X2},{1:X2},{2:X2},{3:X2}]", 
            lengthBuffer[0], lengthBuffer[1], lengthBuffer[2], lengthBuffer[3]);
        
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
    /// Sends a message to the server (auto-encrypts if session established).
    /// </summary>
    public async Task SendMessageAsync(Message message, CancellationToken cancellationToken)
    {
        if (_session.IsEstablished && message.Type == MessageType.Text)
        {
            // Encrypt text messages when session is established
            var encrypted = await _session.EncryptMessageAsync(message);
            await SendRawMessageAsync(encrypted, cancellationToken);
        }
        else
        {
            await SendRawMessageAsync(message, cancellationToken);
        }
    }
    
    /// <summary>
    /// Sends a raw message without encryption.
    /// </summary>
    private async Task SendRawMessageAsync(Message message, CancellationToken cancellationToken)
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
        
        _session.Dispose();
        _stream?.Dispose();
        _client?.Dispose();
        _disposed = true;
    }
}
