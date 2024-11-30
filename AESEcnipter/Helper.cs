using System.Security.Cryptography;
using System.Text;

namespace AESEcnipter
{
    public class Helper
    {
        public static byte[] EncryptWithoutIV(string plainText, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.ECB; // Modo ECB, sem IV
                aesAlg.Key = key;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, null);
                byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                return encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);
            }
        }

        // Método de descriptografia sem IV usando AES ECB
        public static string DecryptWithoutIV(byte[] cipherText, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.ECB; // Modo ECB, sem IV
                aesAlg.Key = key;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, null);
                byte[] plainTextBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                return Encoding.UTF8.GetString(plainTextBytes);
            }
        }
        public static int GenerateRandomInt()      {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] randomBytes = new byte[4]; // 4 bytes = 32 bits
                rng.GetBytes(randomBytes);
                int randomValue = BitConverter.ToInt32(randomBytes, 0);

                // Ajusta para o intervalo desejado
                return new Random(randomValue).Next(0, 1000);
            }
        }

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

        public static bool Validate()
        {
            return true;
        }
    }
}
