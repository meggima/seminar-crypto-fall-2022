using CryptoPrimitives.Common;
using CryptoPrimitives.HomomorphicEncryption;
using FluentAssertions;
using System.Numerics;
using Xunit;
using Xunit.Abstractions;
using Random = CryptoPrimitives.Common.Random;

namespace CryptoPrimitives.Test.HomomorphicEncryption;

public class ElGamalEncryptionTest
{
    private readonly ITestOutputHelper _testOutputHelper;

    public ElGamalEncryptionTest(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Theory]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(255)]
    public void ElGamalEncryption_ShouldWork(int messageLength)
    {
        // Arrange
        ElGamalEncryption encryption = new ElGamalEncryption(WellKnownPrimeOrderGroups.RFC5114_2_3_256, new Random());

        byte[] message = TestUtils.CreateMessage(messageLength);

        _testOutputHelper.WriteLine($"Message: 0x{Convert.ToHexString(message)}");

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
    public void ElGamalEncryptionAdd_ShouldYieldCorrectResult(int aInt, int bInt, int expectedResult)
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

    [Fact]
    public void ElGamalEncryptionAdd_ShouldFail_WhenLongNumbers()
    {
        // Arrange
        ElGamalEncryption encryption = new ElGamalEncryption(WellKnownPrimeOrderGroups.RFC5114_2_3_256, new Random());

        BigInteger a = TestUtils.CreateLargestNumber(256);
        BigInteger b = new BigInteger(2);

        ElGamalKeyPair keys = encryption.GenerateKeys();

        ElGamalEncryptedMessage encryptedMessage1 = encryption.Encrypt(a.ToByteArray(true, true), keys.PublicKey);
        ElGamalEncryptedMessage encryptedMessage2 = encryption.Encrypt(b.ToByteArray(true, true), keys.PublicKey);

        // Act
        ElGamalEncryptedMessage result = encryption.Add(encryptedMessage1, encryptedMessage2);

        byte[] decryptedMessage = encryption.Decrypt(result, keys.PrivateKey);

        // Assert
        BigInteger decryptedMessageNumber = new BigInteger(decryptedMessage, true, true);
        decryptedMessageNumber.Should().NotBe(a * b); // Should actually be the same - but is not due to message length restrictions
    }
}
