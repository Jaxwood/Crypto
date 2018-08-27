# Jaxwood.Crypto [![Build status](https://lorenzen.visualstudio.com/Crypto/_apis/build/status/Crypto-ASP.NET%20Core-CI)](https://lorenzen.visualstudio.com/Crypto/_build/latest?definitionId=104)

A cryptographic library that wraps the .NET `System.Security.Cryptography` library with opinionated defaults.

Features:
- Asymetric encryption using `RSA`
- Symetric encryption using `AES`
- Signing using `RSA`
- Hash using `SHA256`

## Asymetric Encryption

Is supported using the `RSACrypto` class passing in the public and private key, e.g.
```csharp
var rsa = new RSACrypto(pk, p);
```

The class exposes two methods: `EncryptData` and `DecryptData`.

## Symetric Encryption

Is supported using the `AESCryto` class, e.g.

```csharp
var aes = new AESCrypto();
```
Internally the class initializes the key and initialization vector used by the underlaying `AESCryptoServiceProvider`.

The class exposes two methods: `EncryptData` and `DecryptData`.

## Signing

To sign use the class `SignCrypto` passing in the public and private key, e.g.

```csharp
var sign = new SignCrypto(pk, p);
```
The class exposes two main methods: `SignData` and `VerifyData`. Furthermore the class also contains a `HashData` methods to do `SHA256` hashing of the data-to-be-signed.