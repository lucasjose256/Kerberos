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
        var listener = new TcpListener(IPAddress.Any, asPort);
        listener.Start();
        Log("INFO", $"Servidor AS iniciado. Ouvindo na porta {asPort}...");

        while (true)
        {
            try
            {
                using TcpClient client = listener.AcceptTcpClient();
                Log("INFO", "Conexão aceita de " + client.Client.RemoteEndPoint);

                using NetworkStream stream = client.GetStream();
                ProcessClient(stream);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Erro no servidor: " + ex.Message);
            }
        }
    }

    private static void ProcessClient(NetworkStream stream)
    {
        try
        {
            string m1 = ReceiveMessage(stream);
            Log("DEBUG", $"M1 recebido: {m1}");

            if (TryProcessM1(m1, out byte[] m2, out string errorMessage))
            {
                SendMessage(stream, m2);
                Log("INFO", "M2 enviado com sucesso.");
            }
            else
            {
                SendMessage(stream, Encoding.UTF8.GetBytes(errorMessage));
                Log("ERROR", "Falha ao processar M1: " + errorMessage);
            }
        }
        catch (Exception ex)
        {
            Log("ERROR", "Erro ao processar cliente: " + ex.Message);
            SendMessage(stream, Encoding.UTF8.GetBytes("Erro interno no servidor."));
        }
    }

    private static string ReceiveMessage(NetworkStream stream)
    {
        byte[] buffer = new byte[512];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
        return message;
    }

    private static void SendMessage(NetworkStream stream, byte[] messageBytes)
    {
        stream.Write(messageBytes, 0, messageBytes.Length);
    }

    private static bool TryProcessM1(string m1, out byte[] m2, out string errorMessage)
    {
        m2 = null;
        errorMessage = "";

        string[] parts = m1.Split(',', 2);
        if (parts.Length < 2)
        {
            errorMessage = "Formato inválido para M1.";
            return false;
        }

        string clientId = parts[0];
        string encryptedDataBase64 = parts[1];

        if (!IsValidClientId(clientId))
        {
            errorMessage = "Cliente não autorizado.";
            return false;
        }

        byte[] encryptedData = Convert.FromBase64String(encryptedDataBase64);
        byte[] keyASBytes = Encoding.UTF8.GetBytes(keyASClient.PadRight(16, ' '));

        string decryptedMessage;
        try
        {
            decryptedMessage = Helper.DecryptWithoutIV(encryptedData, keyASBytes);
        }
        catch
        {
            errorMessage = "Falha ao descriptografar a mensagem M1.";
            return false;
        }

        Log("DEBUG", $"M1 descriptografado: {decryptedMessage}");
        string[] dataParts = decryptedMessage.Split(',');

        if (dataParts.Length < 3 || !int.TryParse(dataParts[1], out int requestedTime) || !int.TryParse(dataParts[2], out int n1))
        {
            errorMessage = "Dados inválidos em M1 descriptografado.";
            return false;
        }

        byte[] keyCtoTGS = GenerateRandomKey(16);

        string m2Payload = $"{Convert.ToBase64String(keyCtoTGS)},{n1}";
        byte[] encryptedM2Payload = Helper.EncryptWithoutIV(m2Payload, keyASBytes);

        string ticketTGS = $"{clientId},{requestedTime},{Convert.ToBase64String(keyCtoTGS)}";
        byte[] encryptedTicketTGS = Helper.EncryptWithoutIV(ticketTGS, Encoding.UTF8.GetBytes(keyTGS.PadRight(16, ' ')));

    
        string combinedMessage = $"{Convert.ToBase64String(encryptedM2Payload)},{Convert.ToBase64String(encryptedTicketTGS)}";
        m2 = Encoding.UTF8.GetBytes(combinedMessage);

        Log("INFO", "M2 gerado e pronto para envio.");
        return true;
    }

    private static bool IsValidClientId(string clientId)
    {
        return clientId == "17135692347";
    }

    private static byte[] GenerateRandomKey(int size)
    {
        using var rng = new RNGCryptoServiceProvider();
        byte[] key = new byte[size];
        rng.GetBytes(key);
        return key;
    }

    private static void Log(string level, string message)
    {
        Console.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}");
    }
}
