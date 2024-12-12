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
        const int port = 55000;
        const string K_s = "ServiceSecretKey";   // Chave compartilhada com o servidor final
        const string K_tgs = "keyForTGS12345";   // Chave compartilhada com o TGS

        TcpListener listener = new TcpListener(IPAddress.Any, port);
        listener.Start();

        Console.WriteLine("Servidor TGS iniciado na porta " + port);

        while (true)
        {
            using TcpClient client = listener.AcceptTcpClient();
            using NetworkStream stream = client.GetStream();

            try
            {
                // Recebe e processa a mensagem do cliente
                byte[] buffer = new byte[512];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                // Divide a mensagem recebida
                string[] requestParts = request.Split(",", 2);
                string encryptedTicketTGSBase64 = requestParts[0];
                string encryptedDataBase64 = requestParts[1];

                Console.WriteLine("Solicitação recebida. Processando...");

                // Descriptografa o TGS Ticket
                string t_c_tgs = Helper.DecryptWithoutIV(Convert.FromBase64String(encryptedDataBase64), Encoding.UTF8.GetBytes(K_tgs.PadRight(16, ' ')));
                string[] tgsInfo = t_c_tgs.Split(",", 3);
                string clientId = tgsInfo[0];
                string clientKey = tgsInfo[2];  // K_c_tgs

                // Descriptografa os dados do cliente usando K_c_tgs
                string clientData = Helper.DecryptWithoutIV(Convert.FromBase64String(encryptedTicketTGSBase64), Encoding.UTF8.GetBytes(clientKey.PadRight(16, ' ')));
                string[] clientTicket = clientData.Split(",", 4);

                if (clientId != clientTicket[0])
                {
                    Console.WriteLine("Erro: ID do cliente inválido.");
                    continue;
                }

                Console.WriteLine("Validação bem-sucedida. Gerando ticket para o servidor...");

                // Gera uma nova chave de sessão K_c_s
                byte[] K_c_s = GenerateRandomKey(16);
                string K_c_sBase64 = Convert.ToBase64String(K_c_s);
                int timeValidity = 45;  // Tempo de validade do ticket

                // Monta a mensagem P1
                string P1 = $"{K_c_sBase64},{timeValidity},{clientTicket[3]}";
                byte[] encryptedP1 = Helper.EncryptWithoutIV(P1, Encoding.UTF8.GetBytes(clientKey.PadRight(16, ' ')));

                // Monta o ticket para o servidor final
                string TCS = $"{clientId},{timeValidity},{K_c_sBase64}";
                byte[] encryptedTCS = Helper.EncryptWithoutIV(TCS, Encoding.UTF8.GetBytes(K_s.PadRight(16, ' ')));

                // Concatena as mensagens P1 e TCS
                string combinedResponse = $"{Convert.ToBase64String(encryptedP1)},{Convert.ToBase64String(encryptedTCS)}";
                byte[] responseBytes = Encoding.UTF8.GetBytes(combinedResponse);

                // Envia a resposta para o cliente
                stream.Write(responseBytes, 0, responseBytes.Length);

                Console.WriteLine("Ticket gerado e enviado com sucesso.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro ao processar solicitação: " + ex.Message);
            }
        }
    }

    private static byte[] GenerateRandomKey(int size)
    {
        using var rng = new RNGCryptoServiceProvider();
        byte[] key = new byte[size];
        rng.GetBytes(key);
        return key;
    }
}
