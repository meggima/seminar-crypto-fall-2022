using CryptoPrimitives.HomomorphicEncryption;
using FluentAssertions;
using System.Numerics;
using System.Security.Cryptography;
using Xunit;
using Random = CryptoPrimitives.Common.Random;

namespace CryptoPrimitives.Test.HomomorphicEncryption;

public class ElGamalEncryptionTest
{
    [Fact]
    public void ElGamalEncryption_ShouldWork()
    {
        // Arrange
        ElGamalEncryption encryption = new ElGamalEncryption(WellKnownPrimeOrderGroups.RFC5114_2_3_256, new Random());

        byte[] message = CreateMessage();

        // Act
        ElGamalKeyPair keys = encryption.GenerateKeys();

        ElGamalEncryptedMessage encryptedMessage = encryption.Encrypt(message, keys.PublicKey);
        byte[] decryptedMessage = encryption.Decrypt(encryptedMessage, keys.PrivateKey);

        // Assert
        decryptedMessage.Should().Equal(message);
    }

    [Theory]
    [InlineData(1, 1, 1)]
    [InlineData(1, 0, 0)]
    [InlineData(10, 10, 100)]
    [InlineData(1000000, 7, 7000000)]
    public void ElGamalEncryptionAdd_ShouldWork(int aInt, int bInt, int expectedResult)
    {

        // Arrange
        ElGamalEncryption encryption = new ElGamalEncryption(WellKnownPrimeOrderGroups.RFC5114_2_3_256, new Random());

        BigInteger a = new BigInteger(aInt);
        BigInteger b = new BigInteger(bInt);

        ElGamalKeyPair keys = encryption.GenerateKeys();

        ElGamalEncryptedMessage encryptedMessage1 = encryption.Encrypt(a.ToByteArray(true, true), keys.PublicKey);
        ElGamalEncryptedMessage encryptedMessage2 = encryption.Encrypt(b.ToByteArray(true, true), keys.PublicKey);

        // Act
        ElGamalEncryptedMessage result = encryption.Add(encryptedMessage1, encryptedMessage2);

        byte[] decryptedMessage = encryption.Decrypt(result, keys.PrivateKey);

        // Assert
        BigInteger decryptedMessageNumber = new BigInteger(decryptedMessage, true, true);
        decryptedMessageNumber.Should().Be(new BigInteger(expectedResult));
    }

    private static byte[] CreateMessage(int length = 100)
    {
        byte[] message = new byte[length];
        RandomNumberGenerator.Fill(message);
        return message;
    }
}
