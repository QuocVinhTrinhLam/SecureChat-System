using System.Net.Sockets;
using System.Text;
using SecureChat.Core.Models;
using SecureChat.Core.Networking;
using SecureChat.Core.Security.Implementations;

namespace SecureChat.Server;
/// <summary>
/// Handles individual client connections with secure communication support.
/// 
/// Security Design:
/// - Each client gets a unique SecureSession with ephemeral ECDH keys
/// - Key exchange required before encrypted messaging
/// - Uses length-prefixed JSON protocol per MESSAGE_PROTOCOL.md
/// </summary>
public class ClientHandler : IDisposable
{
    /// <summary>User display name.</summary>
    public string User { get; private set; } = "Ẩn danh";
    /// <summary>Client endpoint address.</summary>
    public string ClientEndpoint { get; }
    /// <summary>Whether secure session is established.</summary>
    public bool IsSecureSessionEstablished => _session.IsEstablished;
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private readonly ClientManager _manager;
    private readonly SecureSession _session;
    private readonly JsonMessageSerializer _serializer;
    private readonly string _serverId = "SERVER";
    private readonly string _serverName = "Server";
    private bool _disposed;
    public ClientHandler(TcpClient client, ClientManager manager)
    {
        _client = client;
        _stream = client.GetStream();
        _manager = manager;
        _session = new SecureSession();
        _serializer = new JsonMessageSerializer();
        ClientEndpoint = client.Client.RemoteEndPoint?.ToString() ?? "Unknown";
    }
    /// <summary>
    /// Main handler loop. Performs key exchange then processes messages.
    /// </summary>
    public async Task HandleAsync()
    {
        try
        {
            // Initialize our session (generate ECDH key pair)
            await _session.InitializeAsync();            
            Console.WriteLine($"[SERVER] Phiên bảo mật đã khởi tạo cho {ClientEndpoint}");
            // Send welcome message (plaintext, before encryption established)
            await SendSystemMessageAsync("Chào mừng bạn đến với SecureChat Server. Đang chờ trao đổi khóa...");
            // Main message loop
            while (true)
            {
                var message = await ReceiveMessageAsync();
                if (message == null)
                    break;
                await ProcessMessageAsync(message);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Lỗi xử lý client {ClientEndpoint}: {ex.Message}");
        }
        finally
        {
            Dispose();
        }
    }
    /// <summary>
    /// Process incoming message based on type and session state.
    /// </summary>
    private async Task ProcessMessageAsync(Message message)
    {
        Console.WriteLine($"[SERVER] Nhận tin nhắn loại {message.Type} từ {ClientEndpoint}");
        switch (message.Type)
        {
            case MessageType.KeyExchange:
                await HandleKeyExchangeAsync(message);
                break;
            case MessageType.Encrypted:
                await HandleEncryptedMessageAsync(message);
                break;
            case MessageType.Text:
                await HandleTextMessageAsync(message);
                break;
            case MessageType.Join:
                await HandleJoinAsync(message);
                break;
            case MessageType.Leave:
                // Client is leaving gracefully
                Console.WriteLine($"[SERVER] Client {ClientEndpoint} đã rời khỏi phòng chat");
                break;
            default:
                await SendErrorAsync("Loại tin nhắn không được hỗ trợ");
                break;
        }
    }
    /// <summary>
    /// Handle key exchange message from client.
    /// </summary>
    private async Task HandleKeyExchangeAsync(Message clientKeyMessage)
    {
        try
        {
            Console.WriteLine($"[SERVER] Nhận khóa công khai từ {ClientEndpoint}");           
            // Process client's public key
            await _session.ProcessKeyExchangeMessageAsync(clientKeyMessage);            
            // Send our public key back to client
            var serverKeyMessage = _session.GetKeyExchangeMessage(_serverId, _serverName);
            await SendMessageAsync(serverKeyMessage);
            Console.WriteLine($"[SERVER] Phiên bảo mật đã thiết lập với {ClientEndpoint}");            
            // Notify client that session is established
            await SendSystemMessageAsync("Kết nối bảo mật đã được thiết lập. Mã hóa AES-256-GCM đang hoạt động.");
        }
        catch (SecurityException ex)
        {
            Console.WriteLine($"[SERVER] Lỗi trao đổi khóa: {ex.Message}");
            await SendErrorAsync($"Trao đổi khóa thất bại: {ex.Message}");
        }
    }
    /// <summary>
    /// Handle encrypted message - decrypt, process, respond encrypted.
    /// </summary>
    private async Task HandleEncryptedMessageAsync(Message encryptedMessage)
    {
        if (!_session.IsEstablished)
        {
            await SendErrorAsync("Phiên bảo mật chưa được thiết lập. Vui lòng thực hiện trao đổi khóa trước.");
            return;
        }
        try
        {
            // Decrypt the message
            var decrypted = await _session.DecryptMessageAsync(encryptedMessage);            
            Console.WriteLine($"[SERVER] Tin nhắn đã giải mã từ {decrypted.SenderName}: {decrypted.Content}");
            // Process based on inner message type
            switch (decrypted.Type)
            {
                case MessageType.Text:
                    // Echo back encrypted response
                    var response = Message.CreateTextMessage(
                        _serverId,
                        _serverName,
                        $"Server đã nhận: {decrypted.Content}"
                    );
                    var encryptedResponse = await _session.EncryptMessageAsync(response);
                    await SendMessageAsync(encryptedResponse);
                    break;
                default:
                    Console.WriteLine($"[SERVER] Tin nhắn mã hóa với loại nội dung: {decrypted.Type}");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Lỗi giải mã: {ex.Message}");
            await SendErrorAsync("Không thể giải mã tin nhắn");
        }
    }
    /// <summary>
    /// Handle plaintext text message
    /// </summary>
    private async Task HandleTextMessageAsync(Message message)
    {
        if (_session.IsEstablished)
        {
            // If session is established, warn about unencrypted message
            Console.WriteLine($"[SERVER] Nhận tin nhắn không mã hóa sau khi phiên đã thiết lập từ {ClientEndpoint}");
            await SendSystemMessageAsync("Cảnh báo: Phiên đã mã hóa. Vui lòng gửi tin nhắn dạng Encrypted.");
            return;
        }
        // Process plaintext message
        Console.WriteLine($"[SERVER] [PLAINTEXT] {message.SenderName}: {message.Content}");        
        var response = Message.CreateTextMessage(
            _serverId,
            _serverName,
            $"[Plaintext] Đã nhận: {message.Content}"
        );
        await SendMessageAsync(response);
    }
    /// <summary>
    /// Handle join message.
    /// </summary>
    private async Task HandleJoinAsync(Message message)
    {
        User = message.SenderName;
        Console.WriteLine($"[SERVER] {User} đã tham gia từ {ClientEndpoint}");
        await SendSystemMessageAsync($"Chào mừng {User}! Vui lòng gửi tin nhắn KeyExchange để bắt đầu phiên bảo mật.");
    }
    /// <summary>
    /// Send a raw message using length-prefixed JSON framing.
    /// </summary>
    public async Task SendMessageAsync(Message message)
    {
        if (_disposed) return;

        try
        {
            var bytes = _serializer.Serialize(message);            
            // Write 4-byte length prefix
            var lengthBytes = BitConverter.GetBytes(bytes.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);            
            Console.WriteLine($"[DEBUG] Sending {message.Type} message, length={bytes.Length}, prefix bytes=[{lengthBytes[0]:X2},{lengthBytes[1]:X2},{lengthBytes[2]:X2},{lengthBytes[3]:X2}]");            
            await _stream.WriteAsync(lengthBytes);
            await _stream.WriteAsync(bytes);
            await _stream.FlushAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Lỗi gửi tin nhắn: {ex.Message}");
        }
    }
    /// <summary>
    /// Receive a message using length-prefixed JSON framing.
    /// </summary>
    private async Task<Message?> ReceiveMessageAsync()
    {
        try
        {
            // Read 4-byte length prefix
            var lengthBytes = new byte[4];
            var bytesRead = await _stream.ReadAsync(lengthBytes, 0, 4);            
            if (bytesRead == 0)
                return null; // Connection closed            
            if (bytesRead < 4)
            {
                Console.WriteLine($"[SERVER] Không đủ bytes cho tiền tố độ dài");
                return null;
            }
            // Convert Big-Endian to length
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);
            var messageLength = BitConverter.ToInt32(lengthBytes, 0);
            // Validate message size
            if (messageLength <= 0 || messageLength > JsonMessageSerializer.MaxMessageSize)
            {
                Console.WriteLine($"[SERVER] Kích thước tin nhắn không hợp lệ: {messageLength}");
                return null;
            }
            // Read message payload
            var messageBytes = new byte[messageLength];
            var totalRead = 0;
            while (totalRead < messageLength)
            {
                var read = await _stream.ReadAsync(messageBytes, totalRead, messageLength - totalRead);
                if (read == 0)
                    return null; // Connection closed mid-message
                totalRead += read;
            }
            return _serializer.Deserialize(messageBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Lỗi nhận tin nhắn: {ex.Message}");
            return null;
        }
    }
    /// <summary>
    /// Send a system notification message.
    /// </summary>
    private async Task SendSystemMessageAsync(string content)
    {
        var message = Message.CreateSystemMessage(content);
        await SendMessageAsync(message);
    }
    /// <summary>
    /// Send an error message.
    /// </summary>
    private async Task SendErrorAsync(string error)
    {
        var message = new Message
        {
            Type = MessageType.Error,
            SenderId = _serverId,
            SenderName = _serverName,
            Content = error
        };
        await SendMessageAsync(message);
    }
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _session.Dispose();
        _stream.Close();
        _client.Close();
        _manager.RemoveClient(this);
        Console.WriteLine($"[SERVER] Client {ClientEndpoint} đã ngắt kết nối");
    }
}
