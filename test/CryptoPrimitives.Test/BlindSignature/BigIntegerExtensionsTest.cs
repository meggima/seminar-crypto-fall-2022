using CryptoPrimitives.BlindSignature;
using FluentAssertions;
using System.Numerics;
using Xunit;

namespace CryptoPrimitives.Test.BlindSignature;

public class BigIntegerExtensionsTest
{
    [Theory]
    [InlineData(3, 11, 4)]
    [InlineData(10, 17, 12)]
    [InlineData(3, 7, 5)]
    public void MultiplicativeInverse_ShouldReturnExpectedResult(int number, int modulus, int expectedResult)
    {
        // Act
        BigInteger result = new BigInteger(number).MultiplicativeInverse(modulus);

        // Assert
        result.Should().Be(expectedResult);
    }
}
