using System.Net.Sockets;
using System.Text;

namespace SecureChat.Server
{
    public class ClientHandler : IDisposable
    {
        // Tên người dùng
        public string User { get; private set; } = "Ẩn danh";

        // Địa chỉ client
        public string ClientEndpoint { get; }

        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly ClientManager _manager;

        private readonly StreamReader _reader;
        private readonly StreamWriter _writer;

        public ClientHandler(TcpClient client, ClientManager manager)
        {
            _client = client;
            _stream = client.GetStream();
            _manager = manager;

            ClientEndpoint = client.Client.RemoteEndPoint?.ToString() ?? "Unknown";

            _reader = new StreamReader(_stream, Encoding.Unicode);
            _writer = new StreamWriter(_stream, Encoding.Unicode)
            {
                AutoFlush = true
            };
        }

        public async Task HandleAsync()
        {
            // Gửi thông báo khi client kết nối thành công
            await SendAsync("THÔNG BÁO: Chào mừng bạn đến với Server Chat");

            try
            {
                while (true)
                {
                    string? message = await _reader.ReadLineAsync();

                    // Client đóng kết nối
                    if (message == null)
                        break;

                    await XuLyTinNhanAsync(message);
                }
            }
            catch
            {
                // Bỏ qua lỗi kết nối
            }
            finally
            {
                Dispose();
            }
        }

        private async Task XuLyTinNhanAsync(string message)
        {
            // Xử lý tin nhắn dạng TEXT
            if (message.StartsWith("TEXT:"))
            {
                string noiDung = message.Substring(5);

                Console.WriteLine(
                    $"[CLIENT {ClientEndpoint}] Nội dung gửi: {noiDung}"
                );

                await SendAsync($"PHẢN HỒI: Server đã nhận - {noiDung}");
            }
            else
            {
                await SendAsync("LỖI: Lệnh không hợp lệ");
            }
        }

        public async Task SendAsync(string message)
        {
            await _writer.WriteLineAsync(message);
        }

        public void Dispose()
        {
            _reader.Close();
            _writer.Close();
            _stream.Close();
            _client.Close();

            _manager.RemoveClient(this);

            Console.WriteLine(
                $"[SERVER] Client {ClientEndpoint} đã ngắt kết nối"
            );
        }
    }
}
