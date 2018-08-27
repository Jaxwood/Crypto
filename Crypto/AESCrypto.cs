using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    public class AESCrypto
    {
        public byte[] Key { get; private set; }

        public byte[] IV { get; private set; }

        public AESCrypto()
        {
            this.Key = GenerateRandomNumber(32);
            this.IV = GenerateRandomNumber(16);
        }

        public AESCrypto(byte[] key, byte[] iv)
        {
            this.Key = key;
            this.IV = iv;
        }

        public static byte[] GenerateRandomNumber(int length)
        {
            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var random = new byte[length];
                randomNumberGenerator.GetBytes(random);

                return random;
            }
        }

        public byte[] EncryptData(string dataToEncrypt)
        {
            return this.EncryptData(Encoding.UTF8.GetBytes(dataToEncrypt));
        }

        public byte[] EncryptData(byte[] dataToEncrypt)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = this.Key;
                aes.IV = this.IV;

                using (var memoryStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    cryptoStream.FlushFinalBlock();

                    return memoryStream.ToArray();
                }
            }
        }

        public string DecryptDataToString(byte[] dataToDecrypt)
        {
            return Encoding.UTF8.GetString(this.DecryptData(dataToDecrypt));
        }

        public byte[] DecryptData(byte[] dataToDecrypt)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = this.Key;
                aes.IV = this.IV;

                using (var memoryStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                    cryptoStream.FlushFinalBlock();

                    return memoryStream.ToArray();
                }
            }
        }
    }
}