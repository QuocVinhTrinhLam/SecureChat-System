using Microsoft.Extensions.Logging;

namespace SecureChat.Server;
public class ClientManager
{
    // Danh sách các client đang kết nối
    private readonly List<ClientHandler> _clients = new();
    // Mapping từ username -> ClientHandler để routing
    private readonly Dictionary<string, ClientHandler> _usernameLookup = new(StringComparer.OrdinalIgnoreCase);
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
    // Đăng ký username cho client
    public void RegisterUsername(ClientHandler client, string username)
    {
        lock (_lock)
        {
            _usernameLookup[username] = client;
            _logger.LogInformation("Đã đăng ký username '{Username}' cho {Endpoint}", username, client.ClientEndpoint);
        }
    }
    // Tìm client theo username
    public ClientHandler? GetClientByUsername(string username)
    {
        lock (_lock)
        {
            return _usernameLookup.TryGetValue(username, out var client) ? client : null;
        }
    }
    // Lấy danh sách users online
    public List<string> GetOnlineUsers()
    {
        lock (_lock)
        {
            return _clients.Where(c => !string.IsNullOrEmpty(c.User) && c.User != "Ẩn danh")
                           .Select(c => c.User)
                           .ToList();
        }
    }
    // Lấy tất cả clients (để broadcast)
    public List<ClientHandler> GetAllClients()
    {
        lock (_lock)
        {
            return _clients.ToList();
        }
    }
    // Xóa client khi ngắt kết nối
    public void RemoveClient(ClientHandler client)
    {
        lock (_lock)
        {
            _clients.Remove(client);
            // Xóa khỏi username lookup nếu có
            var usernameEntry = _usernameLookup.FirstOrDefault(kvp => kvp.Value == client);
            if (usernameEntry.Key != null)
            {
                _usernameLookup.Remove(usernameEntry.Key);
                _logger.LogInformation("Đã xóa username '{Username}'", usernameEntry.Key);
            }
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
