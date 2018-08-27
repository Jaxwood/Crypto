using System;
using System.Security.Cryptography;
using Xunit;

namespace Jaxwood.Crypto.Tests
{
    public class SigningCryptoTests
    {
        [Fact]
        public void SigningCrypto_SignVerify_ReturnsCorrectResult()
        {
            var (pk, p) = this.GeneratePublicPrivateKeys();
            var sut = new SignCrypto(pk, p);
            var expected = sut.HashData(Guid.NewGuid().ToString());
            var actual = sut.SignData(expected);
            Assert.True(sut.VerifySignature(expected, actual));
        }

        [Fact]
        public void SigningCrypto_TamperHash_ReturnsCorrectResult()
        {
            var (pk, p) = this.GeneratePublicPrivateKeys();
            var sut = new SignCrypto(pk, p);
            var expected = sut.HashData(Guid.NewGuid().ToString());
            var actual = sut.SignData(expected);
            expected[0]++;
            Assert.False(sut.VerifySignature(expected, actual));
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
