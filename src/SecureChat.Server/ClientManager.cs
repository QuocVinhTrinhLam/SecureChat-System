using Microsoft.Extensions.Logging;

namespace SecureChat.Server
{
    public class ClientManager
    {
        private readonly List<ClientHandler> _clients = new();
        private readonly ILogger<ClientManager> _logger;

        public ClientManager(ILogger<ClientManager> logger)
        {
            _logger = logger;
        }

        public void AddClient(ClientHandler client)
        {
            _clients.Add(client);
            _logger.LogInformation("Client added. Total: {Count}", _clients.Count);
        }

        public void RemoveClient(ClientHandler client)
        {
            _clients.Remove(client);
            _logger.LogInformation("Client removed. Total: {Count}", _clients.Count);
        }
    }
}
