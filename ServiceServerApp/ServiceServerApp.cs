using System.Net.Sockets;
using System.Net;
using System.Text;

public class ServiceServerApp
{
    public static void Main()
    {
        const int port = 54320;
        const string K_s = "ServiceSecretKey";

        TcpListener listener = new TcpListener(IPAddress.Any, port);
        listener.Start();

        Console.WriteLine("Servidor de Serviços iniciado.");

        while (true)
        {
            using TcpClient client = listener.AcceptTcpClient();
            using NetworkStream stream = client.GetStream();

            // Aqui você processaria o ticket do cliente e validaria antes de fornecer o serviço
            byte[] buffer = new byte[256];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            string ticket = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Ticket recebido: " + ticket);

            // Após validar o ticket, forneça o serviço ao cliente
            string response = "Acesso concedido ao serviço!";
            byte[] responseData = Encoding.UTF8.GetBytes(response);
            stream.Write(responseData, 0, responseData.Length);
        }
    }
}
