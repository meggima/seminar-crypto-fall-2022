using CryptoPrimitives.BlindSignature;
using FluentAssertions;
using NSubstitute;
using Xunit;
using Random = CryptoPrimitives.BlindSignature.Random;

namespace CryptoPrimitives.Test.BlindSignature;

public class PrimalityCheckerTest
{
    [Theory]
    [InlineData(1, 1, true)]
    [InlineData(2, 1, true)]
    [InlineData(4, 2, false)]
    [InlineData(17, 3, true)]
    [InlineData(24, 6, false)]
    [InlineData(144, 3, false)]
    public void IsCoPrime_ShouldReturnCorrectResult(int a, int b, bool expectedResult)
    {
        // Arrange
        PrimalityChecker checker = new(Substitute.For<IRandom>());

        // Act
        bool isCoPrime = checker.IsCoprime(a, b);

        // Assert
        isCoPrime.Should().Be(expectedResult);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(3, true)]
    [InlineData(4, false)]
    [InlineData(5, true)]
    [InlineData(6, false)]
    [InlineData(7, true)]
    [InlineData(221, false)]
    [InlineData(7919, true)]
    [InlineData(7920, false)]
    public void IsPrime_ShouldReturnCorrectResult(int a, bool expectedResult)
    {
        // Arrange
        PrimalityChecker checker = new PrimalityChecker(new Random());

        // Act
        bool isPrime = checker.IsPrime(a);

        // Assert
        isPrime.Should().Be(expectedResult);
    }
}
