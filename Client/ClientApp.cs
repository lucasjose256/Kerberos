using AESEcnipter;
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class ClientApp
{
    const string asIp = "127.0.0.1";
    const int asPort = 61000;
    const int tgsPort = 55000;
    const int servicePort = 54320;
    const string clientId = "17135692347";
    const string serviceId = "http_server";
    const string keyASClient = "seguranca123";
      const  int requestedTime = 60;
     string k_c_tgs;
    public static async Task<IPAddress> GetLocalIpAsync()
    {
        var hostName = Dns.GetHostName();
        IPHostEntry localhost = await Dns.GetHostEntryAsync(hostName);
        IPAddress localIpAddress = localhost.AddressList[0];
        Console.WriteLine("Endereço IP local: " + localIpAddress);
        return localIpAddress;
    }

    public static byte[] EncryptMessage(string message, byte[] key)
    {
        return Helper.EncryptWithoutIV(message, key);
    }

    public static async Task<string> SendMessageToServerAsync(string message, string serverIp, int port)
    {
        try
        {
            using (TcpClient client = new TcpClient(serverIp, port))
            using (NetworkStream stream = client.GetStream())
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                await stream.WriteAsync(messageBytes, 0, messageBytes.Length);
                byte[] buffer = new byte[512];
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                return Encoding.UTF8.GetString(buffer, 0, bytesRead);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro ao comunicar com o servidor: " + ex.Message);
            return string.Empty;
        }
    }

    public static async Task<string> AuthenticateWithASAsync(string clientId, int requestedTime, int n1)
    {
        string messageToEncrypt = $"{serviceId},{requestedTime},{n1}";
        byte[] encryptedMessage = EncryptMessage(messageToEncrypt, Encoding.UTF8.GetBytes(keyASClient.PadRight(16, ' ')));

        string message = $"{clientId},{Convert.ToBase64String(encryptedMessage)}";
        return await SendMessageToServerAsync(message, asIp, asPort);
    }

    public static async Task<string> GetTicketFromTGSAsync(string ticketFromAS)
    {
        return await SendMessageToServerAsync(ticketFromAS, asIp, tgsPort);
    }

    public static async Task<string> RequestServiceAccessAsync(string ticketFromTGS)
    {
        return await SendMessageToServerAsync(ticketFromTGS, asIp, servicePort);
    }
    public static string criarM3(string ticketAS) {
      string[]m2=  ticketAS.Split(",", 2);
        string part1=m2[0];
        string t_c_tgs = m2[1];
        byte[] keyAsBytes = Encoding.UTF8.GetBytes(keyASClient.PadRight(16, ' '));

        string part1decripet = Helper.DecryptWithoutIV(Convert.FromBase64String(part1), keyAsBytes);
        string[] message2Part1 = part1decripet.Split(",", 2);
        string chaveSessao = message2Part1[0];
        string numero1 = message2Part1[1];
        Console.WriteLine("m3:chave sessao " +chaveSessao);
        Console.WriteLine("m3:chave sessao " + numero1);

        int n2 = Helper.GenerateRandomInt();
        string messageToEncrypt = $"{clientId},{serviceId},{requestedTime},{n2}";
        byte[] encryptedMessage = EncryptMessage(messageToEncrypt, Encoding.UTF8.GetBytes(chaveSessao.PadRight(16, ' ')));

        string message = $"{Convert.ToBase64String(encryptedMessage)},{t_c_tgs}";
        Console.WriteLine("ENVIADO AO TGS A :  " + message);

        return message;

    }
    public static string criarM5(string ticketAS)
    {
        string[] m2 = ticketAS.Split(",", 2);
        string part1 = m2[0];
        string t_c_tgs = m2[1];
        byte[] keyAsBytes = Encoding.UTF8.GetBytes(keyASClient.PadRight(16, ' '));

        string part1decripet = Helper.DecryptWithoutIV(Convert.FromBase64String(part1), keyAsBytes);
      
        Console.WriteLine("PART1 M4 " );
        Console.WriteLine("PART2" + part1decripet);
       

        return part1decripet;

    }
    public static async Task Main(string[] args)
    {
     
        int n1 = Helper.GenerateRandomInt();

        // Obtendo o IP local
        IPAddress ip = await GetLocalIpAsync();

        try
        {
            // Autenticar com o AS e obter o ticket
            string ticketFromAS = await AuthenticateWithASAsync(clientId, requestedTime, n1);
            Console.WriteLine("Ticket recebido do AS: " + ticketFromAS);
             string m3= criarM3(ticketFromAS);
            // Enviar o ticket para o TGS
            string ticketFromTGS = await GetTicketFromTGSAsync(m3);
            Console.WriteLine("Ticket recebido do TGS: " + ticketFromTGS);
            string m5=  criarM5(ticketFromTGS);
            // Solicitar acesso ao serviço
            string serviceResponse = await RequestServiceAccessAsync(ticketFromTGS);
            Console.WriteLine("Resposta do Servidor de Serviços: " + serviceResponse);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro: " + ex.Message);
        }
    }
}
