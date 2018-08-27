using System;
using System.Security.Cryptography;
using Xunit;

namespace Crypto.Tests
{
    public class RSACryptoTests
    {
        [Fact]
        public void RSACrypto_EncryptDecrypt_ReturnsCorrectResult()
        {
            var (pk, p) = this.GeneratePublicPrivateKeys();
            var sut = new RSACrypto(pk, p);
            var expected = Guid.NewGuid().ToString();

            var cipher = sut.EncryptData(expected);
            var actual = sut.DecryptDataToString(cipher);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void RSACrypto_TamperCipher_ThrowsException()
        {
            var (pk, p) = this.GeneratePublicPrivateKeys();
            var sut = new RSACrypto(pk, p);
            var expected = Guid.NewGuid().ToString();

            var cipher = sut.EncryptData(expected);
            cipher[0]++;
            Assert.ThrowsAny<SystemException>(() => sut.DecryptDataToString(cipher));
        }

        private (string, string) GeneratePublicPrivateKeys()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                var pk = rsa.ExportParameters(false);
                var p = rsa.ExportParameters(true);
                return (rsa.XToXmlString(pk), rsa.XToXmlString(p));
            }
        }
    }
}
