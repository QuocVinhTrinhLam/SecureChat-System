using System.Net.Sockets;
using System.Text;

namespace SecureChat.Server
{
    public class ClientHandler : IDisposable
    {
        // ClientManager yêu cầu
        public string User { get; private set; } = "Anonymous";

        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly ClientManager _manager;

        public ClientHandler(TcpClient client, ClientManager manager)
        {
            _client = client;
            _stream = client.GetStream();
            _manager = manager;
        }

        public async Task HandleAsync()
        {
            byte[] buffer = new byte[1024];

            try
            {
                while (true)
                {
                    int bytesRead =
                        await _stream.ReadAsync(buffer, 0, buffer.Length);

                    if (bytesRead == 0)
                        break;

                    string message =
                        Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    Console.WriteLine($"[{User}] {message}");

                    await SendMessageAsync($"Server received: {message}");
                }
            }
            catch
            {
                // Tạm thời bỏ qua lỗi mạng
            }
            finally
            {
                Dispose();
            }
        }

        // ClientManager sử dụng
        public async Task SendMessageAsync(string message)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            await _stream.WriteAsync(data, 0, data.Length);
        }

        // ClientManager sử dụng
        public void Dispose()
        {
            _client.Close();
            _manager.RemoveClient(this);
            Console.WriteLine("[SERVER] Client disconnected");
        }
    }
}
