using AESEcnipter;
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class ClientApp
{
    // Método assíncrono para obter o IP local
    public static async Task<IPAddress> configIp()
    {
        var hostName = Dns.GetHostName();
        IPHostEntry localhost = await Dns.GetHostEntryAsync(hostName);

        IPAddress localIpAddress = localhost.AddressList[0]; 
        Console.WriteLine("Endereço IP local: " + localIpAddress);
        
        return localIpAddress;
    }

    // Método assíncrono principal
    public static async Task Main(string[] args)
    {
        const string asIp = "127.0.0.1"; 
        const int asPort = 61000;  
        const int tgsPort = 5000;
        const int servicePort = 54320;
        const string clientId = "17135692347";
        const string serviceId = "http_server";
        const string keyASClient = "seguranca123";
        int requestedTime = 60;
        int n1 = Helper.GenerateRandomInt();
        
        // Obtendo o IP
        IPAddress ip = await configIp();

        // Convertendo chave para bytes
        byte[] keyAsBytes = Encoding.UTF8.GetBytes(keyASClient.PadRight(16, ' '));  // Chave com 16 bytes
        
        try
        {
            // Conectar ao servidor de autenticação (AS) e obter o ticket
            using (TcpClient client = new TcpClient(asIp, asPort))
            using (NetworkStream stream = client.GetStream())
            {
                string messageToEncrypt = $"{serviceId},{requestedTime},{n1}";
                byte[] encryptedMessage = Helper.EncryptWithoutIV(messageToEncrypt, keyAsBytes);

                string message = $"{clientId},{Convert.ToBase64String(encryptedMessage)}";
                byte[] m1 = Encoding.UTF8.GetBytes(message);
                await stream.WriteAsync(m1, 0, m1.Length);

                byte[] buffer = new byte[256];
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                Console.WriteLine("Ticket recebido do AS: " + response);  // Ticket recebido do AS

                // Enviar o ticket para o TGS
                using (TcpClient tgsClient = new TcpClient(asIp, tgsPort))
                using (NetworkStream tgsStream = tgsClient.GetStream())
                {
                    byte[] ticketToTgs = Encoding.UTF8.GetBytes(response);
                    await tgsStream.WriteAsync(ticketToTgs, 0, ticketToTgs.Length);
                    Console.WriteLine("Ticket enviado ao TGS...");

                    // Aguardar a resposta do TGS
                    buffer = new byte[512];
                    bytesRead = await tgsStream.ReadAsync(buffer, 0, buffer.Length);
                    string tgsResponse = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Console.WriteLine("Ticket recebido do TGS: " + tgsResponse);  // Ticket de acesso ao serviço

                    // Conectar ao servidor de serviços
                    using (TcpClient serviceClient = new TcpClient(asIp, servicePort))
                    using (NetworkStream serviceStream = serviceClient.GetStream())
                    {
                        byte[] serviceTicket = Encoding.UTF8.GetBytes(tgsResponse);
                        await serviceStream.WriteAsync(serviceTicket, 0, serviceTicket.Length);
                        Console.WriteLine("Ticket enviado ao Servidor de Serviços...");

                        // Aguardar a resposta do servidor de serviços
                        buffer = new byte[512];
                        bytesRead = await serviceStream.ReadAsync(buffer, 0, buffer.Length);
                        string serviceResponse = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        Console.WriteLine("Resposta do Servidor de Serviços: " + serviceResponse);  // Acesso concedido ao serviço
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro: " + ex.Message);
        }
    }
}
