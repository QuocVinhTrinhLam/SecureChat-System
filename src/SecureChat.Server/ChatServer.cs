using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace SecureChat.Server
{
    public class ChatServer
    {
        private readonly TcpListener _listener;
        private readonly ClientManager _clientManager;
        private readonly ILogger<ChatServer> _logger;

        public ChatServer(int port, ILogger<ChatServer> logger)
        {
            _logger = logger;
            _listener = new TcpListener(IPAddress.Any, port);

            _clientManager = new ClientManager(
                LoggerFactory.Create(b => b.AddConsole())
                    .CreateLogger<ClientManager>()
            );
        }

        public async Task StartAsync()
        {
            _listener.Start();
            _logger.LogInformation("Server đang lắng nghe tại cổng 9000");

            while (true)
            {
                TcpClient tcpClient = await _listener.AcceptTcpClientAsync();
                _logger.LogInformation("Có client mới kết nối tới server");

                ClientHandler handler = new ClientHandler(tcpClient, _clientManager);

                _clientManager.AddClient(handler);

                _ = handler.HandleAsync(); // xử lý bất đồng bộ
            }
        }
    }
}
