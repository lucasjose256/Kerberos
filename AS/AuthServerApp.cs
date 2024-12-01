using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using AESEcnipter;

public class AuthServerApp
{
    private const int asPort = 61000;
    private const string keyASClient = "seguranca123"; // Chave compartilhada com o cliente
    private const string keyTGS = "keyForTGS12345";    // Chave compartilhada com o TGS

    public static void Main()
    {
        // Criar o servidor para escutar na porta 61000
        var listener = new TcpListener(IPAddress.Any, asPort);
        listener.Start();
        Console.WriteLine("Servidor AS ouvindo na porta " + asPort);

        // Aguardar uma conexão do cliente
        using TcpClient client = listener.AcceptTcpClient();
        using NetworkStream stream = client.GetStream();

        // Processar a conexão do cliente
        ProcessClientConnection(stream);
    }

    private static void ProcessClientConnection(NetworkStream stream)
    {
        try
        {
            // Receber a mensagem M1 do cliente
            string m1 = ReceiveMessage(stream);
            Console.WriteLine("Mensagem M1 recebida: " + m1);

            // Processar a mensagem M1
            if (TryProcessM1(m1, out byte[] m2, out string errorMessage))
            {
                // Enviar M2 de volta ao cliente
                stream.Write(m2, 0, m2.Length);
                Console.WriteLine("M2 enviado ao cliente.");
            }
            else
            {
                Console.WriteLine(errorMessage);
                SendMessage(stream, errorMessage);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro durante o processo de autenticação: " + ex.Message);
            SendMessage(stream, "Erro no servidor.");
        }
    }

    private static string ReceiveMessage(NetworkStream stream)
    {
        byte[] buffer = new byte[256];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        return Encoding.UTF8.GetString(buffer, 0, bytesRead);
    }

    private static void SendMessage(NetworkStream stream, string message)
    {
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        stream.Write(messageBytes, 0, messageBytes.Length);
    }

    private static bool IsValidClientId(string clientId)
    {
        // Verifique o clientId em um banco de dados ou outra fonte
        // Aqui é apenas um exemplo simples
        return clientId == "17135692347";
    }

    private static bool TryProcessM1(string m1, out byte[] m2, out string errorMessage)
    {
        m2 = null;
        errorMessage = string.Empty;

        // Separar o clientId e a mensagem criptografada
        string[] parts = m1.Split(',', 2);
        if (parts.Length < 2)
        {
            errorMessage = "Mensagem M1 inválida.";
            return false;
        }

        string clientId = parts[0];
        if (!IsValidClientId(clientId))
        {
            errorMessage = "Usuário sem permissão de acesso.";
            return false;
        }

        string encryptedMessageBase64 = parts[1];
        byte[] encryptedMessage = Convert.FromBase64String(encryptedMessageBase64);

        // Gerar a chave de 16 bytes a partir da chave compartilhada (keyASClient)
        byte[] keyAsBytes = Encoding.UTF8.GetBytes(keyASClient.PadRight(16, ' '));

        // Descriptografar a mensagem
        string decryptedMessage = Helper.DecryptWithoutIV(encryptedMessage, keyAsBytes);
        Console.WriteLine("Mensagem descriptografada: " + decryptedMessage);

        // Dividir a mensagem para obter os componentes
        string[] messageParts = decryptedMessage.Split(',');
        if (messageParts.Length < 3)
        {
            errorMessage = "Mensagem descriptografada inválida.";
            return false;
        }

        string serviceId = messageParts[0];
        if (!int.TryParse(messageParts[1], out int requestedTime) ||
            !int.TryParse(messageParts[2], out int n1))
        {
            errorMessage = "Formato inválido dos dados na mensagem descriptografada.";
            return false;
        }

        Console.WriteLine($"ID_S: {serviceId}, T_R: {requestedTime}, N1: {n1}");

        // Gerar K_c_tgs (Chave de sessão entre cliente e TGS)
        byte[] keyCtoTGS = GenerateRandomKey(16);

        string m2Payload = $"{Convert.ToBase64String(keyCtoTGS)},{n1}";
        // Criptografar o m2Payload com a chave keyASClient
        byte[] encryptedM2Payload = Helper.EncryptWithoutIV(m2Payload, Encoding.UTF8.GetBytes(keyASClient.PadRight(16, ' ')));

        // Criar o ticket TGS
        string ticketTGS = $"{clientId},{requestedTime},{Convert.ToBase64String(keyCtoTGS)}";
        // Criptografar o ticket TGS com a chave keyTGS
        byte[] encryptedTicketTGS = Helper.EncryptWithoutIV(ticketTGS, Encoding.UTF8.GetBytes(keyTGS.PadRight(16, ' ')));

        // Converter ambos os bytes para Base64
        string base64EncryptedM2Payload = Convert.ToBase64String(encryptedM2Payload);
        string base64EncryptedTicketTGS = Convert.ToBase64String(encryptedTicketTGS);

        // Concatenar as duas mensagens com uma vírgula
        string combinedMessage = $"{base64EncryptedM2Payload},{base64EncryptedTicketTGS}";

        m2 = Encoding.UTF8.GetBytes( combinedMessage);
        return true;
    }

    private static byte[] GenerateRandomKey(int size)
    {
        using var rng = new RNGCryptoServiceProvider();
        byte[] key = new byte[size];
        rng.GetBytes(key);
        return key;
    }
}


