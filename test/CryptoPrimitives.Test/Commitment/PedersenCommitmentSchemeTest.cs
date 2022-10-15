using CryptoPrimitives.Commitment;
using CryptoPrimitives.Common;
using FluentAssertions;
using System.Numerics;
using Xunit;
using Random = CryptoPrimitives.Common.Random;

namespace CryptoPrimitives.Test.Commitment;

public class PedersenCommitmentSchemeTest
{
    [Fact]
    public void PedersenCommitmentScheme_ShouldReturnTrue_WhenCorrectValue()
    {
        // Arrange
        PedersenCommitmentScheme scheme = new(WellKnownPrimeOrderGroups.RFC5114_2_3_256, new Random());

        PedersenKeyPair pedersenKeyPair = scheme.Setup();

        BigInteger committedValue = BigInteger.One;

        // Act
        PedersenCommitment commitment = scheme.Commit(committedValue, pedersenKeyPair.PublicKey);
        bool isCommitted = scheme.Reveal(commitment, committedValue, pedersenKeyPair.PublicKey); // Same value that was committed to

        // Assert
        isCommitted.Should().BeTrue();
    }

    [Fact]
    public void PedersenCommitmentScheme_ShouldReturnFalse_WhenNotCorrectValue()
    {
        // Arrange
        PedersenCommitmentScheme scheme = new(WellKnownPrimeOrderGroups.RFC5114_2_3_256, new Random());

        PedersenKeyPair pedersenKeyPair = scheme.Setup();
        
        BigInteger committedValue = BigInteger.One;
        BigInteger otherValue = BigInteger.Zero;

        // Act
        PedersenCommitment commitment = scheme.Commit(committedValue, pedersenKeyPair.PublicKey);
        bool isCommitted = scheme.Reveal(commitment, otherValue, pedersenKeyPair.PublicKey); // Other value than was committed to

        // Assert
        isCommitted.Should().BeFalse();
    }
}
