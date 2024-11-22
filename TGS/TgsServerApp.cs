using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

public class TgsServerApp
{
    public static void Main()
    {
        const int port = 5001;
        const string serviceKey = "ServiceSecretKey"; // Chave secreta para o servidor de serviços

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
            byte[] encryptedTicketService = AesEncryptionHelper.Encrypt(ticketService, Encoding.UTF8.GetBytes(serviceKey), new byte[16]);

            // Responde ao cliente com o ticket de acesso ao serviço
            byte[] responseData = Encoding.UTF8.GetBytes(Convert.ToBase64String(encryptedTicketService));
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
