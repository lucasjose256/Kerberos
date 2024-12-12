using AESEcnipter;
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class ClientApp
{
    // Configurações de servidor e cliente
    const string AS_IP = "127.0.0.1";
    const int AS_PORT = 62000;
    const int TGS_PORT = 55000;
    const int SERVICE_PORT = 54320;
    const string CLIENT_ID = "17135692347";
    const string SERVICE_ID = "http_server";
    const string CLIENT_AS_KEY = "seguranca123"; // Chave compartilhada com o AS
    const int REQUESTED_TIME = 60;

    static string sessionKey_TGS = ""; // Chave de sessão com TGS

    /// <summary>
    /// Obtém o endereço IP local.
    /// </summary>
    public static async Task<IPAddress> GetLocalIpAsync()
    {
        var hostName = Dns.GetHostName();
        IPHostEntry localhost = await Dns.GetHostEntryAsync(hostName);
        IPAddress localIpAddress = localhost.AddressList[0];
        Console.WriteLine($"[INFO] Endereço IP local detectado: {localIpAddress}");
        return localIpAddress;
    }

    /// <summary>
    /// Encripta a mensagem usando AES sem IV.
    /// </summary>
    public static byte[] EncryptMessage(string message, byte[] key)
    {
        return Helper.EncryptWithoutIV(message, key);
    }

    /// <summary>
    /// Envia uma mensagem para o servidor especificado e recebe uma resposta.
    /// </summary>
    public static async Task<string> SendMessageToServerAsync(string message, string serverIp, int port)
    {
        try
        {
            Console.WriteLine($"[INFO] Conectando ao servidor {serverIp}:{port}");
            using (TcpClient client = new TcpClient(serverIp, port))
            using (NetworkStream stream = client.GetStream())
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                await stream.WriteAsync(messageBytes, 0, messageBytes.Length);

                Console.WriteLine($"[INFO] Mensagem enviada: {message}");

                byte[] buffer = new byte[512];
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                Console.WriteLine($"[INFO] Resposta recebida: {response}");
                return response;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERRO] Falha na comunicação: {ex.Message}");
            return string.Empty;
        }
    }

    /// <summary>
    /// Autentica o cliente com o AS e recebe o ticket para o TGS.
    /// </summary>
    public static async Task<string> AuthenticateWithASAsync(int nonce1)
    {
        string plaintext = $"{SERVICE_ID},{REQUESTED_TIME},{nonce1}";
        byte[] encryptedMessage = EncryptMessage(plaintext, Encoding.UTF8.GetBytes(CLIENT_AS_KEY.PadRight(16, ' ')));

        string messageToAS = $"{CLIENT_ID},{Convert.ToBase64String(encryptedMessage)}";
        Console.WriteLine($"[STEP 1] Autenticando com o AS. Mensagem enviada: {messageToAS}");
        return await SendMessageToServerAsync(messageToAS, AS_IP, AS_PORT);
    }

    /// <summary>
    /// Cria a mensagem M3 para solicitar um ticket ao TGS.
    /// </summary>
    public static string CreateM3(string responseFromAS)
    {
        string[] parts = responseFromAS.Split(",", 2);
        string encryptedPart = parts[0];
        string ticketTGS = parts[1];

        // Decripta o conteúdo usando a chave do AS
        byte[] keyASBytes = Encoding.UTF8.GetBytes(CLIENT_AS_KEY.PadRight(16, ' '));
        string decryptedPart = Helper.DecryptWithoutIV(Convert.FromBase64String(encryptedPart), keyASBytes);

        string[] sessionData = decryptedPart.Split(",");
        sessionKey_TGS = sessionData[0];
        string nonce1 = sessionData[1];

        Console.WriteLine($"[INFO] Chave de sessão com TGS: {sessionKey_TGS}");

        int nonce2 = Helper.GenerateRandomInt();
        string plaintext = $"{CLIENT_ID},{SERVICE_ID},{REQUESTED_TIME},{nonce2}";
        byte[] encryptedMessage = EncryptMessage(plaintext, Encoding.UTF8.GetBytes(sessionKey_TGS.PadRight(16, ' ')));

        string messageM3 = $"{Convert.ToBase64String(encryptedMessage)},{ticketTGS}";
        Console.WriteLine($"[STEP 2] Mensagem M3 enviada ao TGS: {messageM3}");
        return messageM3;
    }

    /// <summary>
    /// Cria a mensagem M5 para autenticar com o servidor de serviços.
    /// </summary>
    public static string CreateM5(string responseFromTGS)
    {
        string[] parts = responseFromTGS.Split(",", 2);
        string encryptedPart = parts[0];
        string ticketService = parts[1];

        // Decripta usando a chave de sessão com TGS
        byte[] keyTGSBytes = Encoding.UTF8.GetBytes(sessionKey_TGS.PadRight(16, ' '));
        string decryptedPart = Helper.DecryptWithoutIV(Convert.FromBase64String(encryptedPart), keyTGSBytes);

        string[] sessionData = decryptedPart.Split(",");
        string sessionKey_Service = sessionData[0];
        string timeAuthorized = sessionData[1];
        int nonce2 = int.Parse(sessionData[2]);

        Console.WriteLine($"[INFO] Chave de sessão com o servidor: {sessionKey_Service}");

        int nonce3 = Helper.GenerateRandomInt();
        string plaintext = $"{CLIENT_ID},{timeAuthorized},{SERVICE_ID},{nonce3}";
        byte[] encryptedMessage = EncryptMessage(plaintext, Encoding.UTF8.GetBytes(sessionKey_Service.PadRight(16, ' ')));

        string messageM5 = $"{Convert.ToBase64String(encryptedMessage)},{ticketService}";
        Console.WriteLine($"[STEP 3] Mensagem M5 enviada ao servidor: {messageM5}");
        return messageM5;
    }

    /// <summary>
    /// Executa o fluxo completo: AS -> TGS -> Servidor de Serviços.
    /// </summary>
    /// <summary>
    /// Executa o fluxo completo: AS -> TGS -> Servidor de Serviços.
    /// </summary>
    public static async Task Main(string[] args)
    {
        int nonce1 = Helper.GenerateRandomInt();
        IPAddress ip = await GetLocalIpAsync();

        try
        {
            // Etapa 1: Autenticação com o AS
            string ticketFromAS = await AuthenticateWithASAsync(nonce1);

            // Etapa 2: Solicitação de ticket ao TGS
            string messageM3 = CreateM3(ticketFromAS);
            string ticketFromTGS = await SendMessageToServerAsync(messageM3, AS_IP, TGS_PORT);

            Console.WriteLine("\n[INFO] Ticket do TGS recebido:");
            Console.WriteLine(ticketFromTGS);

            // Solicita ao usuário o ticket manualmente
            Console.Write("\n[INPUT] Insira o ticket para o servidor manualmente: ");
            string manualTicket = Console.ReadLine();

            if (string.IsNullOrEmpty(manualTicket))
            {
                Console.WriteLine("[ERRO] Ticket inválido. Encerrando...");
                return;
            }

            // Etapa 3: Solicitação de serviço ao servidor
            string messageM5 = CreateM5(manualTicket);
    

            string serviceResponse = await SendMessageToServerAsync(messageM5, AS_IP, SERVICE_PORT);

            Console.WriteLine($"[FINAL] Resposta do servidor: {serviceResponse}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERRO] {ex.Message}");
        }
    }

}
