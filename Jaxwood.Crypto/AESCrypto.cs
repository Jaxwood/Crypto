using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    /// <summary>
    /// Exposes <see cref="EncryptData(byte[])"/> and <see cref="DecryptData(byte[])"/> using the <see cref="System.Security.Cryptography.AesCryptoServiceProvider"/> class
    /// </summary>
    public class AESCrypto
    {
        /// <summary>
        /// Key used for the AES encryption
        /// </summary>
        public byte[] Key { get; private set; }

        /// <summary>
        /// Initialization vector for the AES encryption
        /// </summary>
        public byte[] IV { get; private set; }

        /// <summary>
        /// Default contstructor that sets the <see cref="Key"/> and <see cref="IV"/>
        /// </summary>
        public AESCrypto()
        {
            this.Key = GenerateRandomNumber(32);
            this.IV = GenerateRandomNumber(16);
        }

        /// <summary>
        /// Constructor overload that allows passing in the <see cref="Key"/> and <see cref="IV"/>
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        public AESCrypto(byte[] key, byte[] iv)
        {
            this.Key = key;
            this.IV = iv;
        }

        /// <summary>
        /// Creates a random number
        /// <para>Used to set <see cref="Key"/> and <see cref="IV"/></para>
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] GenerateRandomNumber(int length)
        {
            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var random = new byte[length];
                randomNumberGenerator.GetBytes(random);

                return random;
            }
        }

        /// <summary>
        /// Encrypt data using <see cref="System.Security.Cryptography.AesCryptoServiceProvider"/>
        /// </summary>
        /// <param name="dataToEncrypt">Accepts <see cref="System.String"/> that is <see cref="System.Text.Encoding.UTF8"/></param>
        /// <returns></returns>
        public byte[] EncryptData(string dataToEncrypt)
        {
            return this.EncryptData(Encoding.UTF8.GetBytes(dataToEncrypt));
        }

        /// <summary>
        /// Encrypt data using <see cref="System.Security.Cryptography.AesCryptoServiceProvider"/>
        /// </summary>
        /// <param name="dataToEncrypt">Accepts <see cref="System.Byte"/> array</param>
        /// <returns></returns>
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

        /// <summary>
        /// Decrypt data using <see cref="System.Security.Cryptography.AesCryptoServiceProvider"/>
        /// </summary>
        /// <param name="dataToDecrypt">Accepts <see cref="System.Byte"/> array that is decrypted</param>
        /// <returns>The decrypted <see cref="System.String"/></returns>
        public string DecryptDataToString(byte[] dataToDecrypt)
        {
            return Encoding.UTF8.GetString(this.DecryptData(dataToDecrypt));
        }

        /// <summary>
        /// Decrypt data using <see cref="System.Security.Cryptography.AesCryptoServiceProvider"/>
        /// </summary>
        /// <param name="dataToDecrypt">Accepts a <see cref="System.Byte"/> array to be encrypted</param>
        /// <returns>The decrypted <see cref="System.Byte"/> array</returns>
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