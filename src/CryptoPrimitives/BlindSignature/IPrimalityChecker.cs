using System.Numerics;

namespace CryptoPrimitives.BlindSignature;

public interface IPrimalityChecker
{
    /// <summary>
    ///     Tests whether numbers <paramref name="a"/> and <paramref name="b"/> are co-prime.
    /// </summary>
    /// <param name="a">The first number.</param>
    /// <param name="b">The second number.</param>
    /// <returns>True if the numbers are co-prime. False otherwise.</returns>
    bool IsCoprime(BigInteger a, BigInteger b);

    /// <summary>
    ///     Tests whether a given number <paramref name="number"/> is prime.
    ///     
    ///     <para>
    ///         Note that some implementations might not always yield a correct answer.
    ///         But they might yield a correct answer in most cases.
    ///     </para>
    /// </summary>
    /// <param name="number">The number.</param>
    /// <returns>True if a given number is prime. False otherwise.</returns>
    bool IsPrime(BigInteger number);
}