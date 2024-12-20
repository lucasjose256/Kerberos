﻿using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using AESEcnipter;

public class AuthServerApp
{
    public static bool IsValidClientId(string clientId)
    {
        // Verifique o clientId em um banco de dados ou outra fonte
        // Aqui é apenas um exemplo simples
        return clientId == "17135692347"; 
    }

    public static void Main()
    {
        const int asPort = 61000;
        const string keyASClient = "seguranca123";  // Chave compartilhada com o cliente

        // Criar o servidor para escutar na porta 61000
        var listener = new TcpListener(IPAddress.Any, asPort);
        listener.Start();
        Console.WriteLine("Servidor AS ouvindo na porta " + asPort);

        // Aguardar uma conexão do cliente
        using TcpClient client = listener.AcceptTcpClient();
        using NetworkStream stream = client.GetStream();

        try
        {
            // Receber a mensagem M1 do cliente
            byte[] buffer = new byte[256];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            string m1 = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Mensagem M1 recebida: " + m1);

            // Separar o clientId e a mensagem criptografada
            string[] parts = m1.Split(',', 2);
            string clientId = parts[0];
            if (IsValidClientId(clientId))
            {
                string encryptedMessageBase64 = parts[1];
                byte[] encryptedMessage = Convert.FromBase64String(encryptedMessageBase64);

                // Gerar a chave de 16 bytes a partir da chave compartilhada (keyASClient)
                byte[] keyAsBytes = Encoding.UTF8.GetBytes(keyASClient);
                if (keyAsBytes.Length > 16)
                {
                    Array.Resize(ref keyAsBytes, 16);  // Reduz para 16 bytes
                }
                else if (keyAsBytes.Length < 16)
                {
                    Array.Resize(ref keyAsBytes, 16);  // Preenche com 0s se for menor que 16 bytes
                }

                // Gerar o IV aleatório
                byte[] iv = new byte[16];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(iv); // O IV aleatório deve ser compartilhado com o cliente
                }

                // Enviar o IV para o cliente junto com a mensagem criptografada
                stream.Write(iv, 0, iv.Length);
                Console.WriteLine("IV enviado ao cliente.");

                // Descriptografar a mensagem
                string decryptedMessage = Helper.DecryptWithoutIV(encryptedMessage, keyAsBytes);
                Console.WriteLine("Mensagem descriptografada: " + decryptedMessage);

                // Exemplo de processamento da mensagem descriptografada
                // Dividir a mensagem para obter os componentes
                string[] messageParts = decryptedMessage.Split(',');
                string serviceId = messageParts[0];
                int requestedTime = int.Parse(messageParts[1]);
                int n1 = int.Parse(messageParts[2]);

                Console.WriteLine($"ID_S: {serviceId}, T_R: {requestedTime}, N1: {n1}");

                // Gerar o ticket de resposta
                string ticket = $"Ticket para {clientId} - Acesso ao serviço {serviceId} concedido.";

                // Enviar o ticket de volta ao cliente
                byte[] ticketBytes = Encoding.UTF8.GetBytes(ticket);
                stream.Write(ticketBytes, 0, ticketBytes.Length);
                Console.WriteLine("Ticket enviado ao cliente.");
            }
            else
            {
                Console.WriteLine("Usuário sem permissão de acesso");
                byte[] errorMsg = Encoding.UTF8.GetBytes("Acesso negado.");
                stream.Write(errorMsg, 0, errorMsg.Length); // Envia a mensagem de erro
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro durante o processo de autenticação: " + ex.Message);
            byte[] errorMsg = Encoding.UTF8.GetBytes("Erro no servidor.");
            stream.Write(errorMsg, 0, errorMsg.Length); // Envia a mensagem de erro
        }
    }
}
