using AESEcnipter;
using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

public class ClientApp
{
    public static void Main()
    {
        const string asIp = "192.168.3.3";
        const int asPort = 54321;  
        const int tgsPort = 5000;
        const int servicePort = 54320;
        const string clientId = "17135692347";
        const string serviceId = "http_server";
        const string keyASClient = "seguranca123";
        int requestedTime = 60;
        int n1= Helper.GenerateRandomInt();

        // Conectar ao servidor de autenticação (AS) e obter o ticket
        using TcpClient client = new TcpClient(asIp, asPort);
        using NetworkStream stream = client.GetStream();

        string messageToEncrypt = $"{serviceId},{requestedTime},{n1}";
        byte[] keyAsBytes = Encoding.UTF8.GetBytes(keyASClient);
        if (keyAsBytes.Length > 16)
        {
            Array.Resize(ref keyAsBytes, 16);  // Reduz para 16 bytes
        }
        else if (keyAsBytes.Length < 16)
        {
            Array.Resize(ref keyAsBytes, 16);  // Preenche com 0s se for menor que 16 bytes
        }
        byte[] iv = new byte[16];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(iv); // Preenche o IV com 16 bytes aleatórios
        }


        byte[] encryptedMessage = Helper.Encrypt(messageToEncrypt, keyAsBytes, iv);

        // Montar a mensagem completa M1: [ID_C + {ID_S + T_R + N1}Kc]
        string message = $"{clientId},{Convert.ToBase64String(encryptedMessage)}";
        byte[] m1 = Encoding.UTF8.GetBytes(message);
        stream.Write(m1, 0, m1.Length);

        byte[] buffer = new byte[256];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
        Console.WriteLine("Ticket recebido do AS: " + response);  // Ticket recebido do AS

        // Agora que temos o ticket do AS, enviamos para o TGS
        try
        {
            using TcpClient tgsClient = new TcpClient(asIp, tgsPort);
            using NetworkStream tgsStream = tgsClient.GetStream();

            // Enviar o ticket para o TGS
            byte[] ticketToTgs = Encoding.UTF8.GetBytes(response);  // O ticket recebido do AS
            tgsStream.Write(ticketToTgs, 0, ticketToTgs.Length);
            Console.WriteLine("Ticket enviado ao TGS...");

            // Aguardar a resposta do TGS
            buffer = new byte[512];  // Aumentando o buffer para garantir que o ticket do TGS seja lido completamente
            bytesRead = tgsStream.Read(buffer, 0, buffer.Length);
            string tgsResponse = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Ticket recebido do TGS: " + tgsResponse);  // Ticket de acesso ao serviço

            // Conectar ao servidor de serviços
            using TcpClient serviceClient = new TcpClient(asIp, servicePort);  // Conexão com o servidor de serviços
            using NetworkStream serviceStream = serviceClient.GetStream();

            // Enviar o ticket para o servidor de serviços
            byte[] serviceTicket = Encoding.UTF8.GetBytes(tgsResponse);  // O ticket recebido do TGS
            serviceStream.Write(serviceTicket, 0, serviceTicket.Length);
            Console.WriteLine("Ticket enviado ao Servidor de Serviços...");

            // Aguardar a resposta do servidor de serviços
            buffer = new byte[512];  // Aumentando o buffer
            bytesRead = serviceStream.Read(buffer, 0, buffer.Length);
            string serviceResponse = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Resposta do Servidor de Serviços: " + serviceResponse);  // Acesso concedido ao serviço
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro: " + ex.Message);
        }
    }
}
