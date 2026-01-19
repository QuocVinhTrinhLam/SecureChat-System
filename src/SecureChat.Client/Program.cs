using SecureChat.Client;
using SecureChat.Core.Utilities;
using System.Text;

class Program
{
    static async Task Main()
    {
        // Set UTF-8 encoding for proper Vietnamese character display
        Console.InputEncoding = Encoding.UTF8;
        Console.OutputEncoding = Encoding.UTF8;

        Console.WriteLine("=== SecureChat Client ===");
        Console.WriteLine();

        // Get username
        Console.Write("Nhập tên của bạn: ");
        var username = Console.ReadLine()?.Trim();
        
        if (string.IsNullOrEmpty(username))
        {
            username = "User" + Random.Shared.Next(1000, 9999);
        }

        // Create client with console logger
        var logger = new ConsoleLogger();
        using var client = new ChatClient("127.0.0.1", 9000, username, logger);

        // Handle Ctrl+C gracefully
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            await client.ConnectAndRunAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine();
            Console.WriteLine("Đã ngắt kết nối.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Lỗi: {ex.Message}");
        }
    }
}
