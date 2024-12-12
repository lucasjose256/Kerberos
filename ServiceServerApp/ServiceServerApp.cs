using System.Net.Sockets;
using System.Net;
using System.Text;
using AESEcnipter; // Biblioteca de criptografia fictícia
using System.Threading;

public class ServiceServerApp
{
    const int port = 54320;
    const string K_s = "ServiceSecretKey"; // Chave secreta compartilhada com o cliente

    public static void Main()
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();

        Console.WriteLine("Servidor iniciado na porta " + port);

        while (true)
        {
            using TcpClient client = listener.AcceptTcpClient();
            using NetworkStream stream = client.GetStream();

            try
            {
                // Receber o ticket do cliente
                byte[] buffer = new byte[256];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                string ticket = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                Console.WriteLine("Ticket recebido: " + ticket);

                // Validar o ticket
                if (!ValidateTicket(ticket, out int tempoLimite))
                {
                    string mensagemErro = "Permissão negada: Ticket inválido.";
                    SendResponse(stream, mensagemErro);
                    Console.WriteLine(mensagemErro);
                    continue; // Passar para a próxima conexão
                }

                // Permitir conexão
                string permissao = $"Permissão concedida. Tempo limite: {tempoLimite} segundos.";
                SendResponse(stream, permissao);
                Console.WriteLine(permissao);

                DateTime inicio = DateTime.Now;

                // Loop para receber mensagens dentro do tempo permitido
                while ((DateTime.Now - inicio).TotalSeconds < tempoLimite)
                {
                    if (stream.DataAvailable)
                    {
                        buffer = new byte[1024]; // Buffer maior para mensagens
                        bytesRead = stream.Read(buffer, 0, buffer.Length);
                        if (bytesRead == 0) break; // Cliente desconectou

                        string mensagem = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        Console.WriteLine("Mensagem recebida do cliente: " + mensagem);

                        // Responder ao cliente
                        string resposta = $"Servidor recebeu: {mensagem}";
                        SendResponse(stream, resposta);
                    }

                    // Pequena pausa para reduzir uso excessivo de CPU
                    Thread.Sleep(100);
                }

                Console.WriteLine("Tempo expirado. Encerrando conexão.");
                SendResponse(stream, "Tempo expirado. Conexão encerrada.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro: {ex.Message}");
                SendResponse(stream, "Erro no servidor. Conexão encerrada.");
            }
        }
    }

    // Valida o ticket e retorna o tempo limite (em segundos)
    static bool ValidateTicket(string ticket, out int tempoLimite)
    {
        tempoLimite = 0;
        try
        {
            string[] ticketArray = ticket.Split(",", 2);
            if (ticketArray.Length != 2)
                return false;

            string part1 = ticketArray[0];
            string part2 = ticketArray[1];

            // Descriptografar part2 usando K_s
            byte[] ksAsBytes = Encoding.UTF8.GetBytes(K_s.PadRight(16, ' '));
            byte[] encryptedPart2 = Convert.FromBase64String(part2);
            string part2Decrypted = Helper.DecryptWithoutIV(encryptedPart2, ksAsBytes);

            string[] part2Array = part2Decrypted.Split(",", 3);
            if (part2Array.Length != 3 || !int.TryParse(part2Array[1], out tempoLimite) || tempoLimite <= 0)
                return false;

            Console.WriteLine("Ticket validado com sucesso.");
            return true;
        }
        catch
        {
            return false; // Retorna falso em caso de falha
        }
    }

    // Envia mensagens para o cliente
    static void SendResponse(NetworkStream stream, string mensagem)
    {
        byte[] responseData = Encoding.UTF8.GetBytes(mensagem);
        stream.Write(responseData, 0, responseData.Length);
    }
}
