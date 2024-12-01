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
        const string K_s = "ServiceSecretKey";
        const string K_tgs = "keyForTGS12345"; 

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
            string[] responseArray = request.Split(",", 2);
            Console.WriteLine("Solicitação recebida1: " + responseArray[0]);
            Console.WriteLine("Solicitação recebida2: " + responseArray[1]);
          
            string t_c_tgs = Helper.DecryptWithoutIV(Convert.FromBase64String( responseArray[1]), Encoding.UTF8.GetBytes(K_tgs.PadRight(16, ' ')));
            string[] response = t_c_tgs.Split(",", 3);
            Console.WriteLine("id: " + response[0]);
            Console.WriteLine("tempo: " + response[1]);
            Console.WriteLine("chave aleatoria k_c_tgs: " + response[2]);
            string ticket = Helper.DecryptWithoutIV(Convert.FromBase64String(responseArray[0]), Encoding.UTF8.GetBytes(response[2].PadRight(16, ' ')));
            string[] ticket_info = ticket.Split(",", 4);

            //o ticket tem id_c,id_server,tempo,numero2
            //preciso validar o ticket com o t_c_tgs
            Console.WriteLine("Tgs id c " + ticket_info[0]);
            Console.WriteLine("Tgs id s " + ticket_info[1]);
            Console.WriteLine("Tgs tempo " + ticket_info[2]);
            Console.WriteLine("Tgs n2 " + ticket_info[3]);
            if (response[0] == ticket_info[0]) {
                byte[] K_c_s = GenerateRandomKey(16);
                int timeA = 45;
               
                string P1 = $"{K_c_s},{timeA}{ticket_info[3]}";
                byte[] P1encript = Helper.EncryptWithoutIV(P1, Encoding.UTF8.GetBytes(response[2].PadRight(16, ' ')));

                string tcs = $"{ticket_info[0]},{timeA},{K_c_s}";
                byte[] tcsEncript = Helper.EncryptWithoutIV(tcs, Encoding.UTF8.GetBytes(K_s.PadRight(16, ' ')));


                byte[] m4 = Encoding.UTF8.GetBytes($"{Encoding.UTF8.GetString(P1encript)},{Encoding.UTF8.GetString(tcsEncript)}"
);
           
                 stream.WriteAsync(m4, 0, m4.Length);
               
         
                Console.WriteLine($"ENVIADO AO cliente o ticket de acessO AO servidor{Encoding.UTF8.GetString(m4)}");

            }
            else
            {
                Console.WriteLine("Erro na validação ");

            }
            //   Console.WriteLine("Solicitação criptografada (Base64): " + oi);

            // Opcional: Exibir bytes brutos como uma string hexadecimal (debug)

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
