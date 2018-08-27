using System.Security.Cryptography;
using System.Text;

namespace Jaxwood.Crypto
{
    /// <summary>
    /// Exposes <see cref="EncryptData(byte[])"/> and <see cref="DecryptData(byte[])"/> using the <see cref="System.Security.Cryptography.RSACryptoServiceProvider"/> class
    /// </summary>
    public class RSACrypto
    {
        private readonly string privateKey;

        private readonly string publicKey;

        /// <summary>
        /// Constructor that accepts <see cref="publicKey"/> and <see cref="privateKey"/> as XML
        /// </summary>
        /// <param name="publicKey">XML representation of the public key</param>
        /// <param name="privateKey">XML representation of the private key</param>
        public RSACrypto(string publicKey, string privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        /// <summary>
        /// Encrypt using <see cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
        /// </summary>
        /// <param name="data">Accepts <see cref="System.String"/> that is the candidate for encryption</param>
        /// <returns>The encrypted data</returns>
        public byte[] EncryptData(string data)
        {
            return this.EncryptData(Encoding.UTF8.GetBytes(data));
        }

        /// <summary>
        /// Encrypt using <see cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
        /// </summary>
        /// <param name="data">Accepts <see cref="System.Byte"/> array to be encrypted</param>
        /// <returns>The encrypted data</returns>
        public byte[] EncryptData(byte[] data)
        {
            byte[] cipherBytes;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.XFromXmlString(this.publicKey);
                cipherBytes = rsa.Encrypt(data, true);
            }

            return cipherBytes;
        }

        /// <summary>
        /// Decrypt using <see cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
        /// </summary>
        /// <param name="data">Accepts <see cref="System.Byte"/> array to be decrypted</param>
        /// <returns>Decrypted <see cref="System.String"/></returns>
        public string DecryptDataToString(byte[] data)
        {
            return Encoding.UTF8.GetString(this.DecryptData(data));
        }

        /// <summary>
        /// Decrypt using <see cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
        /// </summary>
        /// <param name="data">Accepts <see cref="System.Byte"/> array to be decrypted</param>
        /// <returns>Decrypted <see cref="System.Byte"/> array</returns>
        public byte[] DecryptData(byte[] data)
        {
            byte[] plain;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.XFromXmlString(this.privateKey);
                plain = rsa.Decrypt(data, true);
            }
            return plain;
        }

    }
}