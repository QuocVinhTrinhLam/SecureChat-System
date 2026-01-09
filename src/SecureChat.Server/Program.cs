using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Text;

class Program
{
    static void Main()
    {
        var cert = new X509Certificate2("server.pfx", "123456");

        TcpListener listener = new TcpListener(IPAddress.Any, 9000);
        listener.Start();

        Console.WriteLine("Secure Chat Server running on port 9000");

        while (true)
        {
            TcpClient client = listener.AcceptTcpClient();
            Console.WriteLine("Client connected");

            _ = Task.Run(() => HandleClient(client, cert));
        }
    }

    static void HandleClient(TcpClient client, X509Certificate2 cert)
    {
        using var sslStream = new SslStream(
            client.GetStream(),
            false
        );

        sslStream.AuthenticateAsServer(cert, false, false);

        using var reader = new StreamReader(sslStream, Encoding.Unicode);
        using var writer = new StreamWriter(sslStream, Encoding.Unicode) { AutoFlush = true };

        string msg = reader.ReadLine()!;
        Console.WriteLine("[SECURE] " + msg);

        writer.WriteLine("Secure reply: " + msg);
    }
}
