using System.Security.Cryptography;
using System.Text;

namespace Jaxwood.Crypto
{
    /// <summary>
    /// Class for signing using <see cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
    /// </summary>
    public class SignCrypto
    {
        private readonly string privateKey;

        private readonly string publicKey;

        /// <summary>
        /// Constructor that accept <see cref="publicKey"/> and <see cref="privateKey"/> as XML representation
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        public SignCrypto(string publicKey, string privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        /// <summary>
        /// Hash method using <see cref="System.Security.Cryptography.SHA256"/>
        /// </summary>
        /// <param name="dataToHash">Accepts <see cref="System.String"/> to be hashed</param>
        /// <returns>Hashed <see cref="System.Byte"/> array</returns>
        public byte[] HashData(string dataToHash)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));
            }
        }

        /// <summary>
        /// Sign hashed data using <see cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
        /// </summary>
        /// <param name="hashOfDataToSign">Accepts <see cref="System.Byte"/> array that needs to be signed</param>
        /// <returns>Signed data represented as <see cref="System.Byte"/> array</returns>
        public byte[] SignData(byte[] hashOfDataToSign)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.XFromXmlString(this.privateKey);

                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA256");

                return rsaFormatter.CreateSignature(hashOfDataToSign);
            }
        }

        /// <summary>
        /// Verify integrity of signed data using <see cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
        /// </summary>
        /// <param name="hashedData">Accepts hashed data as <see cref="System.Byte"/> array</param>
        /// <param name="signature">Accepts signature as <see cref="System.Byte"/> array</param>
        /// <returns></returns>
        public bool VerifySignature(byte[] hashedData, byte[] signature)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.XFromXmlString(this.publicKey);

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");

                return rsaDeformatter.VerifySignature(hashedData, signature);
            }
        }
    }
}