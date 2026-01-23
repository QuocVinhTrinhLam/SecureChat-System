using SecureChat.Core.Models;
using SecureChat.Core.Utilities;

namespace SecureChat.Client;

/// <summary>
/// Client chat cấp cao điều phối kết nối và tin nhắn.
/// 
/// Thiết kế bảo mật:
/// - Tách riêng xử lý UI/input khỏi các thao tác mạng
/// - Chuẩn bị sẵn cho việc tích hợp security provider trong tương lai
/// - Thông báo tin nhắn dựa trên event để tách biệt UI rõ ràng
/// </summary>
public sealed class ChatClient : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly User _user;
    private readonly ILogger _logger;
    private ServerConnection? _connection;
    private bool _disposed;
    
    /// <summary>
    /// Tạo một chat client mới.
    /// </summary>
    /// <param name="host">Hostname hoặc IP của server.</param>
    /// <param name="port">Cổng của server.</param>
    /// <param name="username">Tên người dùng cho client này.</param>
    /// <param name="logger">Logger cho các sự kiện.</param>
    public ChatClient(string host, int port, string username, ILogger logger)
    {
        _host = host;
        _port = port;
        _logger = logger;
        _user = User.Create(username);
    }
    
    /// <summary>
    /// Kết nối đến server và chạy phiên chat.
    /// </summary>
    public async Task ConnectAndRunAsync(CancellationToken cancellationToken)
    {
        _logger.Info("Đang kết nối đến {0}:{1}...", _host, _port);
        
        _connection = new ServerConnection(_host, _port, _logger);
        await _connection.ConnectAsync(cancellationToken);
        
        _logger.Info("Đã kết nối! Đang thực hiện trao đổi khóa bảo mật...");
        
        // QUAN TRỌNG: Thực hiện trao đổi khóa TRƯỚC KHI bắt đầu receive loop
        // để tránh race condition trên NetworkStream reads
        await _connection.PerformKeyExchangeAsync(_user.Id, _user.Username, cancellationToken);
        
        _logger.Info("---");
        _logger.Info("Phiên chat bảo mật đã sẵn sàng. Nhập tin nhắn và Enter để gửi. Ctrl+C để thoát.");
        _logger.Info("---");
        
        // Đăng ký nhận tin nhắn đến
        _connection.MessageReceived += OnMessageReceived;
        
        // Bắt đầu nhận tin nhắn trong background
        var receiveTask = _connection.StartReceivingAsync(cancellationToken);
        
        // Gửi tin nhắn join (bây giờ đã được mã hóa)
        await SendJoinMessageAsync(cancellationToken);
        
        // Vòng lặp nhập liệu chính
        await RunInputLoopAsync(cancellationToken);
        
        // Gửi tin nhắn leave trước khi ngắt kết nối
        await SendLeaveMessageAsync();
        
        // Chờ receive task hoàn thành
        try
        {
            await receiveTask;
        }
        catch (OperationCanceledException)
        {
            // Đây là hành vi mong đợi
        }
    }
    
    /// <summary>
    /// Gửi tin nhắn join ban đầu đến server.
    /// </summary>
    private async Task SendJoinMessageAsync(CancellationToken cancellationToken)
    {
        var joinMessage = Message.CreateJoinMessage(_user.Id, _user.Username);
        await _connection!.SendMessageAsync(joinMessage, cancellationToken);
        _logger.Security("Đã gửi tin nhắn join cho user: {0}", _user.Username);
    }
    
    /// <summary>
    /// Gửi tin nhắn leave trước khi ngắt kết nối.
    /// </summary>
    private async Task SendLeaveMessageAsync()
    {
        try
        {
            var leaveMessage = Message.CreateLeaveMessage(_user.Id, _user.Username);
            await _connection!.SendMessageAsync(leaveMessage, CancellationToken.None);
        }
        catch
        {
            // Bỏ qua lỗi khi ngắt kết nối
        }
    }
    
    /// <summary>
    /// Vòng lặp chính để đọc input người dùng và gửi tin nhắn.
    /// </summary>
    private async Task RunInputLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Đọc không chặn với hỗ trợ hủy
                var input = await ReadLineAsync(cancellationToken);
                
                if (string.IsNullOrWhiteSpace(input))
                {
                    continue;
                }
                
                Message message;
                
                // Kiểm tra cú pháp tin nhắn trực tiếp: @username message
                if (input.StartsWith("@"))
                {
                    var spaceIndex = input.IndexOf(' ');
                    if (spaceIndex > 1)
                    {
                        var recipientName = input[1..spaceIndex];
                        var content = input[(spaceIndex + 1)..];
                        message = Message.CreateDirectMessage(
                            _user.Id, _user.Username,
                            recipientName, recipientName,
                            content);
                    }
                    else
                    {
                        _logger.Warning("Sử dụng: @username tin nhắn");
                        continue;
                    }
                }
                else
                {
                    // Tin nhắn broadcast
                    message = Message.CreateTextMessage(_user.Id, _user.Username, input);
                }
                
                await _connection!.SendMessageAsync(message, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
    
    /// <summary>
    /// Đọc một dòng từ console với hỗ trợ hủy.
    /// </summary>
    private static async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        // Sử dụng cách tiếp cận polling đơn giản cho console input với hủy
        while (!cancellationToken.IsCancellationRequested)
        {
            if (Console.KeyAvailable)
            {
                return Console.ReadLine();
            }
            
            await Task.Delay(50, cancellationToken);
        }
        
        return null;
    }
    
    /// <summary>
    /// Xử lý tin nhắn nhận được.
    /// </summary>
    private void OnMessageReceived(object? sender, Message message)
    {
        DisplayMessage(message);
    }
    
    /// <summary>
    /// Hiển thị tin nhắn ra console.
    /// </summary>
    private void DisplayMessage(Message message)
    {
        var originalColor = Console.ForegroundColor;
        
        switch (message.Type)
        {
            case MessageType.Text:
                // Kiểm tra xem đây có phải tin nhắn trực tiếp không
                if (!string.IsNullOrEmpty(message.RecipientId))
                {
                    if (message.SenderId == _user.Id)
                    {
                        // Tin nhắn trực tiếp gửi đi
                        Console.ForegroundColor = ConsoleColor.Magenta;
                        Console.WriteLine($"[→ {message.RecipientName}]: {message.Content}");
                    }
                    else
                    {
                        // Tin nhắn trực tiếp nhận vào
                        Console.ForegroundColor = ConsoleColor.Magenta;
                        Console.WriteLine($"[{message.SenderName} → Bạn]: {message.Content}");
                    }
                }
                else if (message.SenderId == _user.Id)
                {
                    // Tin nhắn broadcast của chính mình
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[Bạn]: {message.Content}");
                }
                else
                {
                    // Tin nhắn broadcast của người khác
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[{message.SenderName}]: {message.Content}");
                }
                break;
                
            case MessageType.Join:
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($">>> {message.SenderName} đã tham gia chat");
                break;
                
            case MessageType.Leave:
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"<<< {message.SenderName} đã rời khỏi chat");
                break;
                
            case MessageType.System:
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine($"[Hệ thống]: {message.Content}");
                break;
                
            case MessageType.Error:
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[Lỗi]: {message.Content}");
                break;
                
            default:
                Console.WriteLine($"[{message.Type}]: {message.Content}");
                break;
        }
        
        Console.ForegroundColor = originalColor;
    }
    
    /// <summary>
    /// Giải phóng tài nguyên của client
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        _connection?.Dispose();
        _disposed = true;
    }
}
