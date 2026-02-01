using System.Net.Sockets;
using SecureChat.Core.Models;
using SecureChat.Core.Networking;
using SecureChat.Core.Security.Implementations;
using SecureChat.Core.Utilities;

namespace SecureChat.Client;

public sealed class ServerConnection : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly ILogger _logger;
    private readonly IMessageSerializer _serializer;
    private readonly SecureSession _session;
    private readonly PeerSessionManager _peerManager;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private bool _disposed;
    private string _userId = string.Empty;
    private string _userName = string.Empty;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    
    public bool IsSecure => _session.IsEstablished;
    
    public event EventHandler<Message>? MessageReceived;
    
    public ServerConnection(string host, int port, ILogger logger)
    {
        _host = host;
        _port = port;
        _logger = logger;
        _serializer = new JsonMessageSerializer();
        _session = new SecureSession();
        _peerManager = new PeerSessionManager();
    }
    
    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        _client = new TcpClient();
        
        // Cấu hình tùy chọn socket
        _client.NoDelay = true;
        _client.ReceiveTimeout = 30000;
        _client.SendTimeout = 10000;
        
        try
        {
            await _client.ConnectAsync(_host, _port, cancellationToken);
            _stream = _client.GetStream();
            
            _logger.Security("Kết nối TCP đã thiết lập đến {0}:{1}", _host, _port);
            
            // Khởi tạo phiên bảo mật
            await _session.InitializeAsync();
            _logger.Security("Phiên bảo mật đã khởi tạo (đã tạo khóa ECDH)");
        }
        catch (SocketException ex)
        {
            _logger.Error("Kết nối thất bại: {0}", ex.Message);
            throw;
        }
    }
    
    public async Task PerformKeyExchangeAsync(string userId, string userName, CancellationToken cancellationToken)
    {
        _userId = userId;
        _userName = userName;
        _logger.Info("Đang thực hiện trao đổi khóa với server...");
        
        // Gửi khóa công khai của chúng ta đến server
        var clientKeyMessage = _session.GetKeyExchangeMessage(userId, userName);
        await SendRawMessageAsync(clientKeyMessage, cancellationToken);
        _logger.Security("Đã gửi khóa công khai đến server");
        
        // Chờ phản hồi KeyExchange từ server (có thể nhận tin nhắn System trước)
        Message? serverKeyMessage = null;
        while (serverKeyMessage == null || serverKeyMessage.Type != MessageType.KeyExchange)
        {
            serverKeyMessage = await ReceiveRawMessageAsync(cancellationToken);
            
            if (serverKeyMessage == null)
            {
                throw new InvalidOperationException("Server đã ngắt kết nối");
            }
            
            // Hiển thị tin nhắn system/error nhưng vẫn chờ KeyExchange
            if (serverKeyMessage.Type == MessageType.System)
            {
                _logger.Info("[Server]: {0}", serverKeyMessage.Content);
            }
            else if (serverKeyMessage.Type == MessageType.Error)
            {
                _logger.Error("[Lỗi Server]: {0}", serverKeyMessage.Content);
                throw new InvalidOperationException(serverKeyMessage.Content);
            }
            else if (serverKeyMessage.Type != MessageType.KeyExchange)
            {
                _logger.Warning("Nhận tin nhắn loại {0} trong quá trình key exchange", serverKeyMessage.Type);
            }
        }
        
        // Xử lý khóa của server để thiết lập phiên
        await _session.ProcessKeyExchangeMessageAsync(serverKeyMessage);
        
        _logger.Security("Phiên bảo mật đã thiết lập! (AES-256-GCM)");
    }
    
    public async Task StartReceivingAsync(CancellationToken cancellationToken)
    {
        if (_stream is null)
        {
            throw new InvalidOperationException("Chưa kết nối");
        }
        
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var message = await ReceiveRawMessageAsync(cancellationToken);
                
                if (message is null)
                {
                    _logger.Info("Server đóng kết nối");
                    break;
                }
                
                // Xử lý tin nhắn peer key exchange
                if (message.Type == MessageType.PeerKeyExchange || message.Type == MessageType.PeerKeyExchangeResponse)
                {
                    await HandlePeerKeyExchangeAsync(message, cancellationToken);
                }
                // Nếu được mã hóa và phiên đã thiết lập, giải mã
                else if (message.Type == MessageType.Encrypted)
                {
                    await HandleEncryptedMessageAsync(message);
                }
                else
                {
                    MessageReceived?.Invoke(this, message);
                }
            }
            catch (IOException)
            {
                _logger.Warning("Mất kết nối");
                break;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.Exception(ex, "Lỗi nhận tin nhắn");
            }
        }
    }
    
    private async Task<Message?> ReceiveRawMessageAsync(CancellationToken cancellationToken)
    {
        if (_stream is null) return null;
        
        // Đọc độ dài tin nhắn
        var lengthBuffer = new byte[4];
        var bytesRead = await ReadExactAsync(lengthBuffer, cancellationToken);
        
        if (bytesRead < 4)
        {
            return null; // Server đã ngắt kết nối
        }
        
        _logger.Debug("Bytes độ dài raw: [{0:X2},{1:X2},{2:X2},{3:X2}]", 
            lengthBuffer[0], lengthBuffer[1], lengthBuffer[2], lengthBuffer[3]);
        
        // Chuyển đổi từ big-endian
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(lengthBuffer);
        }
        var messageLength = BitConverter.ToInt32(lengthBuffer, 0);
        
        // Kiểm tra độ dài tin nhắn
        if (messageLength <= 0 || messageLength > JsonMessageSerializer.MaxMessageSize)
        {
            _logger.Warning("Độ dài tin nhắn không hợp lệ: {0}", messageLength);
            return null;
        }
        
        // Đọc body tin nhắn
        var messageBuffer = new byte[messageLength];
        bytesRead = await ReadExactAsync(messageBuffer, cancellationToken);
        
        if (bytesRead < messageLength)
        {
            return null;
        }
        
        return _serializer.Deserialize(messageBuffer);
    }
    
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
    
    public async Task SendMessageAsync(Message message, CancellationToken cancellationToken)
    {
        // Tin nhắn trực tiếp HOẶC File transfer - sử dụng E2E encryption
        if ((!string.IsNullOrEmpty(message.RecipientName) && message.Type == MessageType.Text) ||
            IsFileTransferMessage(message.Type))
        {
            // Với File Transfer: KHÔNG cho phép fallback (Server Blindness)
            // Với Text: Cho phép fallback (backward compatibility/ux)
            bool allowFallback = !IsFileTransferMessage(message.Type);
            
            await SendDirectMessageE2EAsync(message, allowFallback, cancellationToken);
            return;
        }
        
        if (_session.IsEstablished && message.Type == MessageType.Text)
        {
            // Mã hóa tin nhắn broadcast với server session
            var encrypted = await _session.EncryptMessageAsync(message);
            await SendRawMessageAsync(encrypted, cancellationToken);
        }
        else
        {
            await SendRawMessageAsync(message, cancellationToken);
        }
    }
    
    private static bool IsFileTransferMessage(MessageType type)
    {
        return type == MessageType.File || 
               type == MessageType.FileChunk || 
               type == MessageType.FileComplete;
    }
    
    private async Task SendDirectMessageE2EAsync(Message message, bool allowFallback, CancellationToken cancellationToken)
    {
        var recipientName = message.RecipientName!;
        
        // Kiểm tra và thiết lập phiên E2E nếu chưa có
        if (!_peerManager.HasSessionWith(recipientName))
        {
            _logger.Security("Đang thiết lập phiên E2E với {0}...", recipientName);
            
            // Khởi tạo trao đổi khóa với peer
            var keyExchangeMsg = await _peerManager.InitiatePeerSessionAsync(
                recipientName, recipientName, _userId, _userName);
            
            // Gửi yêu cầu trao đổi khóa qua server
            await SendRawMessageAsync(keyExchangeMsg, cancellationToken);
            
            // Chờ phản hồi từ peer với timeout (5 giây)
            try
            {
                await _peerManager.WaitForKeyExchangeAsync(recipientName, 5000);
                _logger.Security("Phiên E2E với {0} đã thiết lập!", recipientName);
            }
            catch (TimeoutException)
            {
                if (!allowFallback)
                {
                    _logger.Error("Không thể gửi file: E2E session timeout. Server blind requirement prevents fallback.");
                    throw new TimeoutException("Không thể thiết lập E2E session cho file transfer. Server không được phép nhìn thấy file.");
                }

                _logger.Warning("E2E timeout, fallback to server encryption.");
                
                // Fallback to server encryption
                if (_session.IsEstablished)
                {
                    var serverEncrypted = await _session.EncryptMessageAsync(message);
                    await SendRawMessageAsync(serverEncrypted, cancellationToken);
                }
                return;
            }
        }
        
        // Mã hóa tin nhắn với khóa E2E
        var encrypted = await _peerManager.EncryptForPeerAsync(message, recipientName);
        await SendRawMessageAsync(encrypted, cancellationToken);
    }
    
    private async Task HandlePeerKeyExchangeAsync(Message message, CancellationToken cancellationToken)
    {
        _logger.Security("Nhận {0} từ {1}", message.Type, message.SenderName);
        
        // Xử lý và lấy phản hồi (nếu có)
        var response = await _peerManager.ProcessPeerKeyExchangeAsync(message, _userId, _userName);
        
        if (response != null)
        {
            // Gửi phản hồi public key về cho peer qua server
            await SendRawMessageAsync(response, cancellationToken);
            _logger.Security("Phiên E2E với {0} đã thiết lập!", message.SenderName);
        }
    }
    
    private async Task HandleEncryptedMessageAsync(Message encryptedMessage)
    {
        try
        {
            Message decrypted;
            
            // Thử giải mã với peer session (E2E) nếu có sender
            var senderName = encryptedMessage.SenderName;
            if (!string.IsNullOrEmpty(senderName) && _peerManager.HasSessionWith(senderName))
            {
                try 
                {
                    decrypted = await _peerManager.DecryptFromPeerAsync(encryptedMessage, senderName);
                }
                catch (Exception)
                {
                    // Nếu giải mã peer thất bại (VD: tin nhắn broadcast từ user này nhưng qua server),
                    // thử fallback sang giải mã server bên dưới
                    decrypted = await _session.DecryptMessageAsync(encryptedMessage);
                }
            }
            else if (_session.IsEstablished)
            {
                // Fallback: giải mã với server session
                decrypted = await _session.DecryptMessageAsync(encryptedMessage);
            }
            else
            {
                _logger.Warning("Không thể giải mã tin nhắn - không có session phù hợp");
                return;
            }
            
            MessageReceived?.Invoke(this, decrypted);
        }
        catch (Exception ex)
        {
            _logger.Error("Lỗi giải mã: {0}", ex.Message);
        }
    }
    
    public bool HasE2ESessionWith(string peerName)
    {
        return _peerManager.HasSessionWith(peerName);
    }
    
    private async Task SendRawMessageAsync(Message message, CancellationToken cancellationToken)
    {
        if (_stream is null)
        {
            throw new InvalidOperationException("Chưa kết nối");
        }
        
        var messageBytes = _serializer.Serialize(message);
        
        // Tạo tiền tố độ dài
        var lengthBytes = BitConverter.GetBytes(messageBytes.Length);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(lengthBytes);
        }
        
        // Thread-safe write
        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            // Ghi độ dài + tin nhắn
            await _stream.WriteAsync(lengthBytes, cancellationToken);
            await _stream.WriteAsync(messageBytes, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
        }
        finally
        {
            _sendLock.Release();
        }
    }
    
    public void Dispose()
    {
        if (_disposed) return;
        
        // Dispose lock
        _sendLock.Dispose();

        _peerManager.Dispose();
        _session.Dispose();
        _stream?.Dispose();
        _client?.Dispose();
        _disposed = true;
    }
}

