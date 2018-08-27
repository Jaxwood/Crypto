using System.Security.Cryptography;
using System.Text;

namespace Jaxwood.Crypto
{
    public class RSACrypto
    {
        private string privateKey;
        private string publicKey;

        public RSACrypto(string publicKey, string privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public byte[] EncryptData(string data)
        {
            return this.EncryptData(Encoding.UTF8.GetBytes(data));
        }

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

        public string DecryptDataToString(byte[] data)
        {
            return Encoding.UTF8.GetString(this.DecryptData(data));
        }

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