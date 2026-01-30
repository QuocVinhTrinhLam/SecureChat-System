using System.Net.Sockets;
using System.Text;
using SecureChat.Core.Models;
using SecureChat.Core.Networking;
using SecureChat.Core.Security.Implementations;

namespace SecureChat.Server;
/// <summary>
/// Xử lý kết nối client và hỗ trợ phiên bảo mật.
/// </summary>
public class ClientHandler : IDisposable
{
    public string User { get; private set; } = "Ẩn danh";
    public string ClientEndpoint { get; }
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
    /// Vòng lặp chính xử lý trao đổi khóa và tin nhắn.
    /// </summary>
    public async Task HandleAsync()
    {
        try
        {
            // Khởi tạo phiên
            await _session.InitializeAsync();            
            Console.WriteLine($"[SERVER] Đã khởi tạo phiên bảo mật cho {ClientEndpoint}");

            await SendSystemMessageAsync("Chào mừng đến SecureChat Server. Đang chờ trao đổi khóa...");
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
    private async Task ProcessMessageAsync(Message message)
    {
        Console.WriteLine($"[SERVER] Nhận tin nhắn loại {message.Type} từ {ClientEndpoint}");
        switch (message.Type)
        {
            case MessageType.KeyExchange:
                await HandleKeyExchangeAsync(message);
                break;
            case MessageType.PeerKeyExchange:
            case MessageType.PeerKeyExchangeResponse:
                await ForwardPeerKeyExchangeAsync(message);
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
                // Client rời khỏi một cách hợp lệ
                Console.WriteLine($"[SERVER] Client {ClientEndpoint} đã rời khỏi phòng chat");
                break;
            case MessageType.File:
            case MessageType.FileChunk:
            case MessageType.FileComplete:
                await HandleFileTransferAsync(message);
                break;
            default:
                await SendErrorAsync("Loại tin nhắn không được hỗ trợ");
                break;
        }
    }
    private async Task HandleKeyExchangeAsync(Message clientKeyMessage)
    {
        try
        {
            Console.WriteLine($"[SERVER] Nhận được khóa công khai từ {ClientEndpoint}");           
            
            await _session.ProcessKeyExchangeMessageAsync(clientKeyMessage);            
            
            var serverKeyMessage = _session.GetKeyExchangeMessage(_serverId, _serverName);
            await SendMessageAsync(serverKeyMessage);
            Console.WriteLine($"[SERVER] Đã thiết lập phiên bảo mật với {ClientEndpoint}");            
            
            await SendSystemMessageAsync("Kết nối bảo mật đã được thiết lập. Mã hóa AES-256-GCM đang hoạt động.");
        }
        catch (SecurityException ex)
        {
            Console.WriteLine($"[SERVER] Lỗi trao đổi khóa: {ex.Message}");
            await SendErrorAsync($"Trao đổi khóa thất bại: {ex.Message}");
        }
    }
    /// <summary>
    /// Chuyển tiếp tin nhắn mã hóa mà không giải mã nội dung.
    /// </summary>
    private async Task HandleEncryptedMessageAsync(Message encryptedMessage)
    {
        if (!_session.IsEstablished)
        {
            await SendErrorAsync("Phiên bảo mật chưa được thiết lập. Vui lòng thực hiện trao đổi khóa trước.");
            return;
        }
        
        // Kiểm tra xem đây có phải tin nhắn có người nhận cụ thể không
        if (!string.IsNullOrEmpty(encryptedMessage.RecipientName))
        {
            await RouteDirectMessageAsync(encryptedMessage);
        }
        else
        {
            // Broadcast đến tất cả clients (hành vi hiện tại để tương thích ngược)
            await BroadcastMessageAsync(encryptedMessage);
        }
    }
    
    /// <summary>
    /// Chuyển tiếp tin nhắn trao đổi khóa ngang hàng (peer).
    /// </summary>
    private async Task ForwardPeerKeyExchangeAsync(Message message)
    {
        var recipientName = message.RecipientName;
        
        if (string.IsNullOrEmpty(recipientName))
        {
            await SendErrorAsync("Peer key exchange cần có người nhận");
            return;
        }
        
        var recipient = _manager.GetClientByUsername(recipientName);
        
        if (recipient == null)
        {
            Console.WriteLine($"[SERVER] Peer key exchange: User '{recipientName}' không online");
            await SendErrorAsync($"User '{recipientName}' không online");
            return;
        }
        
        Console.WriteLine($"[SERVER] Chuyển tiếp {message.Type} từ {message.SenderName} đến {recipientName}");
        
        // Chuyển tiếp trực tiếp, không giải mã hay sửa đổi
        await recipient.SendMessageAsync(message);
    }
    
    /// <summary>
    /// Xử lý tin nhắn truyền file bằng cách mã hóa lại cho người nhận.
    /// </summary>
    private async Task HandleFileTransferAsync(Message message)
    {
        if (!_session.IsEstablished)
        {
            await SendErrorAsync("Phiên bảo mật chưa được thiết lập. Vui lòng thực hiện trao đổi khóa trước.");
            return;
        }
        
        var recipientName = message.RecipientName;
        if (string.IsNullOrEmpty(recipientName))
        {
            await SendErrorAsync("File transfer cần có người nhận cụ thể.");
            return;
        }
        
        var recipient = _manager.GetClientByUsername(recipientName);
        if (recipient == null)
        {
            Console.WriteLine($"[SERVER] File transfer: User '{recipientName}' không online");
            await SendErrorAsync($"User '{recipientName}' không online");
            return;
        }
        
        if (!recipient.IsSecureSessionEstablished)
        {
            await SendErrorAsync($"User '{recipientName}' chưa thiết lập phiên bảo mật");
            return;
        }
        
        try
        {
            // Giải mã tin nhắn file sử dụng phiên của người gửi
            var decrypted = await _session.DecryptMessageAsync(message);
            
            var typeStr = message.Type switch
            {
                MessageType.File => "metadata",
                MessageType.FileChunk => $"chunk {decrypted.FileChunkData?.ChunkIndex ?? 0}",
                MessageType.FileComplete => "complete",
                _ => "unknown"
            };
            Console.WriteLine($"[SERVER] Routing file {typeStr} từ {decrypted.SenderName} đến {recipientName}");
            
            // Mã hóa lại với khóa phiên của người nhận
            var reEncrypted = await recipient.EncryptForClientAsync(decrypted);
            await recipient.SendMessageAsync(reEncrypted);
            
            // Chỉ echo lại cho người gửi với File metadata (không echo chunks để tránh spam)
            if (message.Type == MessageType.File)
            {
                var senderEcho = await EncryptForClientAsync(decrypted);
                await SendMessageAsync(senderEcho);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Lỗi routing file transfer: {ex.Message}");
            await SendErrorAsync($"Không thể gửi file đến {recipientName}");
        }
    }
    
    /// <summary>
    /// Chuyển tiếp tin nhắn trực tiếp đến người nhận cụ thể
    /// Server giải mã với khóa của người gửi và mã hóa lại với khóa của người nhận
    /// Lưu ý: Để mã hóa E2E thật sự, clients cần trao đổi khóa trực tiếp
    /// </summary>
    /// <summary>
    /// Định tuyến tin nhắn trực tiếp. Sử dụng chuyển tiếp mù cho E2E, ngược lại dùng relay.
    /// </summary>
    private async Task RouteDirectMessageAsync(Message encryptedMessage)
    {
        var recipientName = encryptedMessage.RecipientName!;
        var recipient = _manager.GetClientByUsername(recipientName);
        
        if (recipient == null)
        {
            Console.WriteLine($"[SERVER] User '{recipientName}' không online");
            await SendErrorAsync($"User '{recipientName}' không online");
            return;
        }
        
        // Kiểm tra xem tin nhắn này có phải E2E không
        // Nếu KeyId trong metadata KHÁC KeyId của phiên Server-Client hiện tại, đó là tin nhắn E2E
        var msgKeyId = encryptedMessage.SecurityMetadata?.KeyId;
        var isE2EMessage = msgKeyId != _session.SessionId;

        if (isE2EMessage)
        {
            Console.WriteLine($"[SERVER] Blind Forwarding E2E tin nhắn từ {encryptedMessage.SenderName} đến {recipientName} (KeyId mismatch)");
            // Chế độ E2E: Forward nguyên vẹn, không giải mã
            await recipient.SendMessageAsync(encryptedMessage);
            return;
        }

        // Chế độ Relay (Fallback)
        if (!recipient.IsSecureSessionEstablished)
        {
            await SendErrorAsync($"User '{recipientName}' chưa thiết lập phiên bảo mật (Server Relay)");
            return;
        }
        
        try
        {
            // Giải mã tin nhắn sử dụng phiên của người gửi
            var decrypted = await _session.DecryptMessageAsync(encryptedMessage);
            Console.WriteLine($"[SERVER] Relaying (Fallback) tin nhắn từ {decrypted.SenderName} đến {recipientName}");
            
            // Mã hóa lại với khóa phiên của người nhận
            var reEncrypted = await recipient.EncryptForClientAsync(decrypted);
            await recipient.SendMessageAsync(reEncrypted);
            
            // Echo lại cho người gửi (mã hóa lại với khóa của người gửi)
            // Lưu ý: Chỉ echo trong chế độ Relay. E2E client tự handle UI.
            var senderEcho = await EncryptForClientAsync(decrypted);
            await SendMessageAsync(senderEcho);
            
            Console.WriteLine($"[SERVER] Đã echo tin nhắn relay về cho {decrypted.SenderName}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Lỗi routing tin nhắn relay: {ex.Message}");
            await SendErrorAsync($"Không thể gửi tin nhắn đến {recipientName}");
        }
    }
    
    /// <summary>
    /// Mã hóa tin nhắn cho client này sử dụng khóa phiên của họ.
    /// </summary>
    public async Task<Message> EncryptForClientAsync(Message plaintext)
    {
        return await _session.EncryptMessageAsync(plaintext);
    }
    
    /// <summary>
    /// Broadcast tin nhắn đến tất cả client đang kết nối.
    /// </summary>
    private async Task BroadcastMessageAsync(Message encryptedMessage)
    {
        try
        {
            // Giải mã tin nhắn sử dụng phiên của người gửi
            var decrypted = await _session.DecryptMessageAsync(encryptedMessage);
            Console.WriteLine($"[SERVER] Broadcasting tin nhắn từ {decrypted.SenderName} đến tất cả clients");
            
            var allClients = _manager.GetAllClients();
            foreach (var client in allClients)
            {
                try
                {
                    if (client.IsSecureSessionEstablished)
                    {
                        // Mã hóa lại với khóa phiên của người nhận
                        var reEncrypted = await client.EncryptForClientAsync(decrypted);
                        await client.SendMessageAsync(reEncrypted);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SERVER] Lỗi gửi broadcast đến {client.ClientEndpoint}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Lỗi giải mã broadcast: {ex.Message}");
        }
    }
    private async Task HandleTextMessageAsync(Message message)
    {
        if (_session.IsEstablished)
        {
            // Nếu phiên đã thiết lập, cảnh báo về tin nhắn không mã hóa
            Console.WriteLine($"[SERVER] Nhận tin nhắn không mã hóa sau khi phiên đã thiết lập từ {ClientEndpoint}");
            await SendSystemMessageAsync("Cảnh báo: Phiên đã mã hóa. Vui lòng gửi tin nhắn dạng Encrypted.");
            return;
        }
        // Xử lý tin nhắn không mã hóa
        Console.WriteLine($"[SERVER] [PLAINTEXT] {message.SenderName}: {message.Content}");        
        var response = Message.CreateTextMessage(
            _serverId,
            _serverName,
            $"[Plaintext] Đã nhận: {message.Content}"
        );
        await SendMessageAsync(response);
    }
    private async Task HandleJoinAsync(Message message)
    {
        User = message.SenderName;
        
        // Đăng ký username để routing
        _manager.RegisterUsername(this, User);
        
        Console.WriteLine($"[SERVER] {User} đã tham gia từ {ClientEndpoint}");
        
        // Gửi danh sách users cho client mới
        var onlineUsers = _manager.GetOnlineUsers();
        await SendUserListAsync(onlineUsers);
        
        // Gửi tin nhắn chào mừng
        await SendSystemMessageAsync($"Chào mừng {User}!\nGửi tin nhắn riêng: @username nội dung\nVui lòng gửi tin nhắn KeyExchange để bắt đầu phiên bảo mật.");
        
        // Thông báo cho các clients khác và gửi danh sách users mới
        var joinNotification = Message.CreateJoinMessage(message.SenderId, User);
        var userListMessage = Message.CreateUserListMessage(onlineUsers);
        var allClients = _manager.GetAllClients();
        foreach (var client in allClients)
        {
            if (client != this)
            {
                try
                {
                    await client.SendMessageAsync(joinNotification);
                    await client.SendMessageAsync(userListMessage);
                }
                catch { /* bỏ qua */ }
            }
        }
    }
    
    /// <summary>
    /// Gửi danh sách user đang online.
    /// </summary>
    private async Task SendUserListAsync(List<string> users)
    {
        var message = Message.CreateUserListMessage(users);
        await SendMessageAsync(message);
    }
    public async Task SendMessageAsync(Message message)
    {
        if (_disposed) return;

        try
        {
            var bytes = _serializer.Serialize(message);            
            // Ghi 4-byte tiền tố độ dài
            var lengthBytes = BitConverter.GetBytes(bytes.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);            
            Console.WriteLine($"[DEBUG] Đang gửi tin nhắn {message.Type}, length={bytes.Length}, prefix bytes=[{lengthBytes[0]:X2},{lengthBytes[1]:X2},{lengthBytes[2]:X2},{lengthBytes[3]:X2}]");            
            await _stream.WriteAsync(lengthBytes);
            await _stream.WriteAsync(bytes);
            await _stream.FlushAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Lỗi gửi tin nhắn: {ex.Message}");
        }
    }
    private async Task<Message?> ReceiveMessageAsync()
    {
        try
        {
            // Đọc 4-byte tiền tố độ dài
            var lengthBytes = new byte[4];
            var bytesRead = await _stream.ReadAsync(lengthBytes, 0, 4);            
            if (bytesRead == 0)
                return null; // Kết nối đã đóng            
            if (bytesRead < 4)
            {
                Console.WriteLine($"[SERVER] Không đủ bytes cho tiền tố độ dài");
                return null;
            }
            // Chuyển đổi Big-Endian sang độ dài
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);
            var messageLength = BitConverter.ToInt32(lengthBytes, 0);
            // Kiểm tra kích thước tin nhắn
            if (messageLength <= 0 || messageLength > JsonMessageSerializer.MaxMessageSize)
            {
                Console.WriteLine($"[SERVER] Kích thước tin nhắn không hợp lệ: {messageLength}");
                return null;
            }
            // Đọc payload tin nhắn
            var messageBytes = new byte[messageLength];
            var totalRead = 0;
            while (totalRead < messageLength)
            {
                var read = await _stream.ReadAsync(messageBytes, totalRead, messageLength - totalRead);
                if (read == 0)
                    return null; // Kết nối đóng giữa chừng
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
    private async Task SendSystemMessageAsync(string content)
    {
        var message = Message.CreateSystemMessage(content);
        await SendMessageAsync(message);
    }
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
        
        // Thông báo cho các clients khác về việc user rời đi
        if (User != "Ẩn danh")
        {
            var leaveNotification = Message.CreateLeaveMessage(User, User);
            var allClients = _manager.GetAllClients();
            foreach (var client in allClients)
            {
                if (client != this)
                {
                    try
                    {
                        client.SendMessageAsync(leaveNotification).Wait();
                    }
                    catch { /* bỏ qua */ }
                }
            }
        }
        
        _session.Dispose();
        _stream.Close();
        _client.Close();
        _manager.RemoveClient(this);
        
        // Gửi danh sách users mới sau khi remove
        if (User != "Ẩn danh")
        {
            var updatedUsers = _manager.GetOnlineUsers();
            var userListMessage = Message.CreateUserListMessage(updatedUsers);
            var remainingClients = _manager.GetAllClients();
            foreach (var client in remainingClients)
            {
                try
                {
                    client.SendMessageAsync(userListMessage).Wait();
                }
                catch { /* bỏ qua */ }
            }
        }
        
        Console.WriteLine($"[SERVER] Client {ClientEndpoint} đã ngắt kết nối");
    }
}
