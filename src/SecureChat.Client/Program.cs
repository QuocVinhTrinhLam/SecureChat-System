using System.Net.Sockets;
using System.Text;

class Program
{
    static async Task Main()
    {
        Console.InputEncoding = Encoding.Unicode;
        Console.OutputEncoding = Encoding.Unicode;

        Console.WriteLine("Đang kết nối tới Server Chat...");

        TcpClient client = new TcpClient();
        client.Connect("127.0.0.1", 9000);

        Console.WriteLine("Đã kết nối tới server");

        NetworkStream stream = client.GetStream();
        StreamReader reader = new StreamReader(stream, Encoding.Unicode);
        StreamWriter writer = new StreamWriter(stream, Encoding.Unicode)
        {
            AutoFlush = true
        };

        // Nhận thông báo từ server
        string? welcome = await reader.ReadLineAsync();
        if (welcome != null)
        {
            Console.WriteLine(welcome);
        }

        while (true)
        {
            Console.Write("Nhập tin nhắn: ");
            string? input = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(input))
            {
                Console.WriteLine("Đã thoát khỏi chương trình client");
                break;
            }

            // Gửi tin nhắn theo protocol
            await writer.WriteLineAsync("TEXT: " + input);

            // Nhận phản hồi từ server
            string? response = await reader.ReadLineAsync();
            if (response == null)
            {
                Console.WriteLine("Server đã ngắt kết nối");
                break;
            }
            Console.WriteLine(response);
        }
        stream.Close();
        client.Close();
    }
}
