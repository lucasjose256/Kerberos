using System;
using System.Net.Sockets;
using System.Text;

public class ClientApp
{
    public static void Main()
    {
        const string asIp = "192.168.3.3";
        const int asPort = 54321;

        using TcpClient client = new TcpClient(asIp, asPort);
        using NetworkStream stream = client.GetStream();

        // ID do Cliente e mensagem de autenticação
        string clientId = "Client1";
        string serviceId = "Service1";
        string nonce = "N1"; // Número aleatório para verificação

        string message = $"{clientId},{serviceId},{nonce}";
        byte[] data = Encoding.UTF8.GetBytes(message);
        stream.Write(data, 0, data.Length);

        // Recebe a resposta do AS (ticket cifrado e chave de sessão para TGS)
        byte[] buffer = new byte[256];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

        Console.WriteLine("Ticket recebido do AS: " + response);

        // O próximo passo seria se comunicar com o TGS usando o ticket recebido
    }
}
