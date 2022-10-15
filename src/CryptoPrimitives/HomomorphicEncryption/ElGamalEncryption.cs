using CryptoPrimitives.Common;
using System.Numerics;

namespace CryptoPrimitives.HomomorphicEncryption;

/// <summary>
///     Implements the ElGamal crypto system including the homomorphic multiplication.
/// </summary>
public class ElGamalEncryption
{
    private readonly PrimeOrderGroup _primeOrderGroup;
    private readonly IRandom _random;

    /// <summary>
    ///     Creates an instance of the ElGamal encryption scheme.
    /// </summary>
    /// <param name="primeOrderGroup">The prime order group to use.</param>
    /// <param name="random">The random number generator to use.</param>
    public ElGamalEncryption(PrimeOrderGroup primeOrderGroup, IRandom random)
    {
        _primeOrderGroup = primeOrderGroup;
        _random = random;
    }

    /// <summary>
    ///     Generates a public/private key pair for the encryption.
    /// </summary>
    /// <returns>The key pair.</returns>
    public ElGamalKeyPair GenerateKeys()
    {
        BigInteger privateKey = _random.GetRandomNumber(_primeOrderGroup.SubgroupSize);

        BigInteger publicKey = BigInteger.ModPow(_primeOrderGroup.Generator, privateKey, _primeOrderGroup.Prime);

        return new(new ElGamalPublicKey(publicKey), new ElGamalPrivateKey(privateKey));
    }

    /// <summary>
    ///     Encrypts a message using the ElGamal encryption scheme.
    /// </summary>
    /// <param name="message">The message to encrypt.</param>
    /// <param name="publicKey">The public key to use for encryption.</param>
    /// <returns>The encrypted message.</returns>
    public ElGamalEncryptedMessage Encrypt(byte[] message, ElGamalPublicKey publicKey)
    {
        BigInteger messageAsNumber = new BigInteger(message, true, true);

        BigInteger r = _random.GetRandomNumber(_primeOrderGroup.SubgroupSize);

        BigInteger c = BigInteger.ModPow(_primeOrderGroup.Generator, r, _primeOrderGroup.Prime);

        BigInteger d = BigInteger.ModPow(publicKey.Base, r, _primeOrderGroup.Prime) * messageAsNumber % _primeOrderGroup.Prime;

        return new(c, d);
    }

    /// <summary>
    ///     Decrypts a message.
    /// </summary>
    /// <param name="encryptedMessage">The message to be decrypted.</param>
    /// <param name="privateKey">The private key to use for decryption.</param>
    /// <returns>The decrypted message.</returns>
    public byte[] Decrypt(ElGamalEncryptedMessage encryptedMessage, ElGamalPrivateKey privateKey)
    {
        BigInteger inverse = BigInteger.ModPow(encryptedMessage.C, privateKey.Exponent, _primeOrderGroup.Prime).MultiplicativeInverse(_primeOrderGroup.Prime);
        BigInteger decryptedMessageAsNumber = encryptedMessage.D * inverse % _primeOrderGroup.Prime;

        return decryptedMessageAsNumber.ToByteArray(true, true);
    }

    /// <summary>
    ///     Implements the homomorphic multiplication of two encrypted messages.
    /// </summary>
    /// <param name="encryptedMessage1">The first encryptedMessage.</param>
    /// <param name="encryptedMessage2">The second encryptedMessage.</param>
    /// <returns>An encrypted message representing the result of the multiplication.</returns>
    public ElGamalEncryptedMessage Add(ElGamalEncryptedMessage encryptedMessage1, ElGamalEncryptedMessage encryptedMessage2)
    {
        BigInteger newC = encryptedMessage1.C * encryptedMessage2.C % _primeOrderGroup.Prime;
        BigInteger newD = encryptedMessage1.D * encryptedMessage2.D % _primeOrderGroup.Prime;
        return new(newC, newD);
    }
}

public record ElGamalPublicKey(BigInteger Base);

public record ElGamalPrivateKey(BigInteger Exponent);

public record ElGamalKeyPair(ElGamalPublicKey PublicKey, ElGamalPrivateKey PrivateKey);

public record ElGamalEncryptedMessage(BigInteger C, BigInteger D);
