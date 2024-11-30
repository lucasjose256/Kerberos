using AESEcnipter;
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

public class TgsServerApp
{
    public static void Main()
    {
        const int port = 5000;
        const string K_s = "ServiceSecretKey";
        const string K_tgs = "TgsSecretKey1234"; 

        TcpListener listener = new TcpListener(IPAddress.Any, port);
        listener.Start();

        Console.WriteLine("Servidor de Tickets (TGS) iniciado.");

        while (true)
        {
            using TcpClient client = listener.AcceptTcpClient();
            using NetworkStream stream = client.GetStream();

            // Aqui você receberia o ticket do cliente e o validaria
            // Depois emitiria um novo ticket para o cliente acessar o serviço desejado

            byte[] buffer = new byte[256];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Solicitação recebida: " + request);

            // Aqui você deve criptografar o ticket de acesso ao serviço
            string ticketService = $"Ticket para o serviço, com dados do cliente.";
            byte[] encryptedTicketService = Helper.Encrypt(ticketService, Encoding.UTF8.GetBytes(K_s), new byte[16]);

            // Responde ao cliente com o ticket de acesso ao serviço
            byte[] responseData = Encoding.UTF8.GetBytes(Convert.ToBase64String(encryptedTicketService));
            stream.Write(responseData, 0, responseData.Length);
        }
    }
   
}
