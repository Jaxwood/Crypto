using System;
using Xunit;

namespace Crypto.Tests
{
    public class AESCryptoTests
    {
        [Fact]
        public void AESCrypto_EncryptDecrypt_ReturnsCorrectResult()
        {
            var sut = new AESCrypto();
            var expected = Guid.NewGuid().ToString();
            var cipher = sut.EncryptData(expected);
            var actual = sut.DecryptDataToString(cipher);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void AESCrypto_TamperData_AreNotEqual()
        {
            var sut = new AESCrypto();
            var expected = Guid.NewGuid().ToString();
            var cipher = sut.EncryptData(expected);
            cipher[0]++;
            var actual = sut.DecryptDataToString(cipher);
            Assert.NotEqual(expected, actual);
        }
    }
}
