using CryptoPrimitives.Common;
using System.Numerics;

namespace CryptoPrimitives.Commitment;

/// <summary>
///     Implements the Pedersen commitment scheme
///     <see href="https://en.wikipedia.org/wiki/Commitment_scheme#A_perfectly_binding_scheme_based_on_the_discrete_log_problem_and_beyond"/>
/// </summary>
public class PedersenCommitmentScheme
{
    private readonly PrimeOrderGroup _primeOrderGroup;
    private readonly IRandom _random;

    public PedersenCommitmentScheme(PrimeOrderGroup primeOrderGroup, IRandom random)
    {
        _primeOrderGroup = primeOrderGroup;
        _random = random;
    }

    /// <summary>
    ///     Setup a Pedersen key pair for commitments.
    /// </summary>
    /// <returns>The Pedersen key pair.</returns>
    public PedersenKeyPair Setup()
    {
        BigInteger a = _random.GetRandomNumber(_primeOrderGroup.SubgroupSize);
        BigInteger h = BigInteger.ModPow(_primeOrderGroup.Generator, a, _primeOrderGroup.Prime);

        return new(new(h), new(a));
    }

    /// <summary>
    ///     Commit to a given <paramref name="value"/>.
    /// </summary>
    /// <param name="value">The value to commit to.</param>
    /// <param name="sharedKey">The Pedersen shared key.</param>
    /// <returns>A Pedersen commitment to the given value.</returns>
    public PedersenCommitment Commit(BigInteger value, PedersenSharedKey sharedKey)
    {
        BigInteger r = _random.GetRandomNumber(_primeOrderGroup.SubgroupSize);

        BigInteger c = BigInteger.ModPow(_primeOrderGroup.Generator, value, _primeOrderGroup.Prime)
            * BigInteger.ModPow(sharedKey.Base, r, _primeOrderGroup.Prime)
            % _primeOrderGroup.Prime;

        return new(c, r);
    }

    /// <summary>
    ///     Checks whether the sender committed to the given value.
    /// </summary>
    /// <param name="commitment">The commitment.</param>
    /// <param name="value">The value to check.</param>
    /// <param name="sharedKey">The Pedersen shared key.</param>
    /// <returns>True if the sender committed to the given value. False otherwise.</returns>
    public bool Reveal(PedersenCommitment commitment, BigInteger value, PedersenSharedKey sharedKey)
    {
        BigInteger cPrime = BigInteger.ModPow(_primeOrderGroup.Generator, value, _primeOrderGroup.Prime)
            * BigInteger.ModPow(sharedKey.Base, commitment.Random, _primeOrderGroup.Prime)
            % _primeOrderGroup.Prime;

        return cPrime == commitment.Commitment;
    }
}

public record PedersenSharedKey(BigInteger Base);

public record PedersenPrivateKey(BigInteger Exponent);

public record PedersenKeyPair(PedersenSharedKey PublicKey, PedersenPrivateKey PrivateKey);

public record PedersenCommitment(BigInteger Commitment, BigInteger Random);