using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace SecureChat.Server
{
    public class ChatServer
    {
        private readonly int _port;
        private readonly TcpListener _listener;
        private readonly ClientManager _clientManager;
        private readonly ILogger<ChatServer> _logger;

        public ChatServer(int port, ILogger<ChatServer> logger)
        {
            _port = port;
            _logger = logger;

            _listener = new TcpListener(IPAddress.Any, _port);

            _clientManager = new ClientManager(
                LoggerFactory.Create(b => b.AddConsole())
                    .CreateLogger<ClientManager>()
            );
        }

        public async Task StartAsync()
        {
            _listener.Start();
            _logger.LogInformation("Server listening on port {Port}", _port);

            while (true)
            {
                TcpClient tcpClient = await _listener.AcceptTcpClientAsync();
                _logger.LogInformation("New client connected");

                ClientHandler handler =
                    new ClientHandler(tcpClient, _clientManager);

                _clientManager.AddClient(handler);

                _ = handler.HandleAsync(); // chạy bất đồng bộ
            }
        }
    }
}
