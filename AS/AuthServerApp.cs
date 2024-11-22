using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

public class AuthServerApp
{
    public static void Main()
    {
        const int port = 5000;
        const string tgsKey = "TgsSecretKey1234"; // Chave secreta compartilhada com TGS

        TcpListener listener = new TcpListener(IPAddress.Any, port);
        listener.Start();

        Console.WriteLine("Servidor de Autenticação (AS) iniciado.");

        while (true)
        {
            using TcpClient client = listener.AcceptTcpClient();
            using NetworkStream stream = client.GetStream();

            // Recebe solicitação do cliente
            byte[] buffer = new byte[256];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Solicitação recebida: " + request);

            // Processa o pedido (parse do ID do cliente e serviço)
            string[] parts = request.Split(",");
            string clientId = parts[0];
            string serviceId = parts[1];
            string nonce = parts[2];

            // Gera uma chave de sessão e ticket para o TGS
            byte[] sessionKey = Aes.Create().Key;
            string ticketTgs = $"{clientId},{DateTime.UtcNow.AddMinutes(5)},{Convert.ToBase64String(sessionKey)}";
            byte[] ticketTgsEncrypted = AesEncryptionHelper.Encrypt(ticketTgs, Encoding.UTF8.GetBytes(tgsKey), new byte[16]);

            // Responde ao cliente com o ticket para o TGS e a chave de sessão
            string response = $"{Convert.ToBase64String(sessionKey)},{Convert.ToBase64String(ticketTgsEncrypted)}";
            byte[] responseData = Encoding.UTF8.GetBytes(response);
            stream.Write(responseData, 0, responseData.Length);
        }
    }

    public class AesEncryptionHelper
    {
        public static byte[] Encrypt(string text, byte[] key, byte[] iv)
        {
            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;
            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using var swEncrypt = new StreamWriter(csEncrypt);
            swEncrypt.Write(text);

            return msEncrypt.ToArray();
        }

        public static string Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;
            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var msDecrypt = new MemoryStream(cipherText);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);

            return srDecrypt.ReadToEnd();
        }
    }
}
