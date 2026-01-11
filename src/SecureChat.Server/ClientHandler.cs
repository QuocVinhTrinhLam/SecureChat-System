using System.Net.Sockets;
using System.Text;
using System.IO;

namespace SecureChat.Server
{
    public class ClientHandler : IDisposable
    {
        // Tên người dùng
        public string User { get; private set; } = "Ẩn danh";

        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly StreamReader _reader;
        private readonly StreamWriter _writer;
        private readonly ClientManager _manager;

        public ClientHandler(TcpClient client, ClientManager manager)
        {
            _client = client;
            _stream = client.GetStream();

            _reader = new StreamReader(_stream, Encoding.Unicode);
            _writer = new StreamWriter(_stream, Encoding.Unicode)
            {
                AutoFlush = true
            };

            _manager = manager;
        }

        public async Task HandleAsync()
        {
            // Gửi thông báo khi client kết nối
            await SendAsync("THÔNG BÁO: Chào mừng bạn đến với Server Chat");

            try
            {
                while (true)
                {
                    // Đọc theo DÒNG
                    string? message = await _reader.ReadLineAsync();

                    // Client đóng kết nối
                    if (message == null)
                        break;

                    await XuLyTinNhanAsync(message.Trim());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Lỗi xử lý client: " + ex.Message);
            }
            finally
            {
                Dispose();
            }
        }

        private async Task XuLyTinNhanAsync(string message)
        {
            // Protocol: TEXT:<nội dung>
            if (message.StartsWith("TEXT:"))
            {
                string noiDung = message.Substring(5);

                Console.WriteLine($"[{User}] {noiDung}");

                await SendAsync("PHẢN HỒI: Server đã nhận tin nhắn");
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
            Console.WriteLine("Client đã ngắt kết nối khỏi server");
        }
    }
}
