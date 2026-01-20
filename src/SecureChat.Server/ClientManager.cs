using Microsoft.Extensions.Logging;

namespace SecureChat.Server;
public class ClientManager
{
    // Danh sách các client đang kết nối
    private readonly List<ClientHandler> _clients = new();
    // Đối tượng khóa để đảm bảo an toàn luồng
    private readonly object _lock = new();
    private readonly ILogger<ClientManager> _logger;
    public ClientManager(ILogger<ClientManager> logger)
    {
        _logger = logger;
    }
    // Thêm client mới
    public void AddClient(ClientHandler client)
    {
        lock (_lock)
        {
            _clients.Add(client);
            _logger.LogInformation(
                "Client kết nối từ {Endpoint}. Tổng số client: {Count}",
                client.ClientEndpoint,
                _clients.Count
            );
        }
    }
    // Xóa client khi ngắt kết nối
    public void RemoveClient(ClientHandler client)
    {
        lock (_lock)
        {
            _clients.Remove(client);
            _logger.LogInformation(
                "Client ngắt kết nối từ {Endpoint}. Tổng số client còn lại: {Count}",
                client.ClientEndpoint,
                _clients.Count
            );
        }
    }
    // Lấy số lượng client hiện tại
    public int GetClientCount()
    {
        lock (_lock)
        {
            return _clients.Count;
        }
    }
}
