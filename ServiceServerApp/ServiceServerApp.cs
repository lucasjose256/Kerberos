using System.Net.Sockets;
using System.Net;
using System.Text;
using AESEcnipter;

public class ServiceServerApp
{
    const int port = 54320;
    const string K_s = "ServiceSecretKey";
    public static void Main()
    {
        

        TcpListener listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();

        Console.WriteLine("Servidor de Serviços iniciado.");

        while (true)
        {
            using TcpClient client = listener.AcceptTcpClient();
            using NetworkStream stream = client.GetStream();

            // Aqui você processaria o ticket do cliente e validaria antes de fornecer o serviço
            byte[] buffer = new byte[256];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            string ticket = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Ticket recebido: " + ticket);
            createM6(ticket);
            // Após validar o ticket, forneça o serviço ao cliente
            string response = "Acesso concedido ao serviço!";
            byte[] responseData = Encoding.UTF8.GetBytes(response);
            stream.Write(responseData, 0, responseData.Length);
        }
    }


    static void createM6(string ticket)
    {
        // Separar o ticket em duas partes
        string[] ticketArray = ticket.Split(",", 2);
        if (ticketArray.Length != 2)
        {
            throw new ArgumentException("Ticket inválido. Certifique-se de que está no formato correto.");
        }

        // Partes do ticket
        string part1 = ticketArray[0]; // Encriptado com Kcs
        string part2 = ticketArray[1]; // Encriptado com Ks

        // Decodificar e preparar chave Ks
        byte[] ksAsBytes = Encoding.UTF8.GetBytes(K_s.PadRight(16, ' ')); // Ajustar tamanho da chave para 16 bytes
        byte[] encryptedPart2;

        try
        {
            encryptedPart2 = Convert.FromBase64String(part2); // Decodificar part2 de base64
        }
        catch (FormatException)
        {
            throw new ArgumentException("Part2 não está no formato base64 esperado.");
        }

        // Descriptografar part2 com Ks
        string part2Decrypted = Helper.DecryptWithoutIV(encryptedPart2, ksAsBytes);

        // Separar os campos de part2
        string[] part2Array = part2Decrypted.Split(",", 3);
        if (part2Array.Length != 3)
        {
            throw new ArgumentException("Part2 descriptografado está mal formatado.");
        }

        string id = part2Array[0];
        string tempoA = part2Array[1];
        string kcs = part2Array[2];

        // Preparar chave Kcs
        byte[] kcsAsBytes = Encoding.UTF8.GetBytes(kcs.PadRight(16, ' ')); // Ajustar tamanho da chave

        // Decodificar part1 de base64 antes de descriptografar
        byte[] encryptedPart1;
        try
        {
            encryptedPart1 = Convert.FromBase64String(part1);
        }
        catch (FormatException)
        {
            throw new ArgumentException("Part1 não está no formato base64 esperado.");
        }

        // Descriptografar part1 com Kcs
        string part1Decrypted = Helper.DecryptWithoutIV(encryptedPart1, kcsAsBytes);

        // Exibir os resultados
        Console.WriteLine("Ticket Decriptado (Part2): " + part2Decrypted);
        Console.WriteLine("Ticket Decriptado (Part1): " + part1Decrypted);
    }


}
