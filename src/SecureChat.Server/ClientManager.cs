using Microsoft.Extensions.Logging;

namespace SecureChat.Server
{
    public class ClientManager
    {
        // Danh sách các client đang kết nối
        private readonly List<ClientHandler> _clients = new();

        private readonly ILogger<ClientManager> _logger;

        public ClientManager(ILogger<ClientManager> logger)
        {
            _logger = logger;
        }

        // Thêm client mới
        public void AddClient(ClientHandler client)
        {
            _clients.Add(client);
            _logger.LogInformation(
                "Đã thêm client mới. Tổng số client: {Count}",
                _clients.Count
            );
        }

        // Xóa client khi ngắt kết nối
        public void RemoveClient(ClientHandler client)
        {
            _clients.Remove(client);
            _logger.LogInformation(
                "Đã xóa client. Tổng số client còn lại: {Count}",
                _clients.Count
            );
        }
    }
}
