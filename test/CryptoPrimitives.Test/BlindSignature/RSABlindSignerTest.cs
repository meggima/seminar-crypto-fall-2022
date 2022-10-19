using CryptoPrimitives.BlindSignature;
using CryptoPrimitives.Common;
using FluentAssertions;
using NSubstitute;
using System.Numerics;
using Xunit;
using Xunit.Abstractions;
using Random = CryptoPrimitives.Common.Random;

namespace CryptoPrimitives.Test.BlindSignature;

public class RSABlindSignerTest
{
    private readonly ITestOutputHelper _testOutputHelper;

    public RSABlindSignerTest(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Theory]
    [InlineData(3, 11, 7, 3)]
    [InlineData(7, 17, 5, 77)]
    public void GenerateKey_ShouldGenerateKey(int p, int q, int e, int d)
    {
        // Arrange
        IRandom random = Substitute.For<IRandom>();
        random.GetRandomNumber(Arg.Any<BigInteger>()).Returns(p, q, e);

        IPrimalityChecker primalityChecker = Substitute.For<IPrimalityChecker>();
        primalityChecker.IsPrime(p).Returns(true);
        primalityChecker.IsPrime(q).Returns(true);

        primalityChecker.IsCoprime(e, (p - 1) * (q - 1)).Returns(true);

        RSABlindSigner rsaBlindSigner = new(random, primalityChecker);

        // Act
        (RSAPublicKey PublicKey, RSAPrivateKey PrivateKey) keys = rsaBlindSigner.GenerateKey(10);

        // Assert
        keys.PublicKey.N.Should().Be(p * q);
        keys.PublicKey.PublicExponent.Should().Be(e);

        keys.PrivateKey.N.Should().Be(p * q);
        keys.PrivateKey.PrivateExponent.Should().Be(d);
    }

    [Fact]
    public void Signing_ShouldWork()
    {
        // Arrange
        Random random = new Random();
        RSABlindSigner rsaBlindSigner = new(random, new PrimalityChecker(random));

        (RSAPublicKey PublicKey, RSAPrivateKey PrivateKey) keys = rsaBlindSigner.GenerateKey(100);

        _testOutputHelper.WriteLine($"Public key: ({keys.PublicKey.N}, {keys.PublicKey.PublicExponent})");
        _testOutputHelper.WriteLine($"Private key: ({keys.PrivateKey.N}, {keys.PrivateKey.PrivateExponent})");

        byte[] message = TestUtils.CreateMessage();

        _testOutputHelper.WriteLine($"Message: 0x{Convert.ToHexString(message)}");

        // Act
        (byte[] BlindedMessage, BigInteger BlindingFactor) blinded = rsaBlindSigner.Blind(message, keys.PublicKey);
        BigInteger blindSignature = rsaBlindSigner.Sign(blinded.BlindedMessage, keys.PrivateKey);
        BigInteger signature = rsaBlindSigner.Unblind(blindSignature, blinded.BlindingFactor, keys.PublicKey);

        bool result = rsaBlindSigner.Verify(signature, message, keys.PublicKey);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void Signgin_ShouldFail_WhenWrongMessage()
    {
        // Arrange
        Random random = new Random();
        RSABlindSigner rsaBlindSigner = new(random, new PrimalityChecker(random));

        (RSAPublicKey PublicKey, RSAPrivateKey PrivateKey) keys = rsaBlindSigner.GenerateKey(100);

        _testOutputHelper.WriteLine($"Public key: ({keys.PublicKey.N}, {keys.PublicKey.PublicExponent})");
        _testOutputHelper.WriteLine($"Private key: ({keys.PrivateKey.N}, {keys.PrivateKey.PrivateExponent})");

        byte[] message1 = TestUtils.CreateMessage();
        byte[] message2 = TestUtils.CreateMessage();

        _testOutputHelper.WriteLine($"Message1: 0x{Convert.ToHexString(message1)}");
        _testOutputHelper.WriteLine($"Message2: 0x{Convert.ToHexString(message2)}");


        // Act
        (byte[] BlindedMessage, BigInteger BlindingFactor) blinded = rsaBlindSigner.Blind(message1, keys.PublicKey);
        BigInteger blindSignature = rsaBlindSigner.Sign(blinded.BlindedMessage, keys.PrivateKey);
        BigInteger signature = rsaBlindSigner.Unblind(blindSignature, blinded.BlindingFactor, keys.PublicKey);

        bool result = rsaBlindSigner.Verify(signature, message2, keys.PublicKey); // Verify wrong message

        // Assert
        result.Should().BeFalse();
    }
}
